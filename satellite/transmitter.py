"""
AegisLEO Secure Satellite Telemetry Transmitter
Transport-Hardened RF Version with Selective session_init Recovery

Created by: Jamie Grunewald
Date: 2026-03-26
Version: v0.12.0

What changed in v0.12.0
-----------------------
1. Fixed telemetry object usage in the main TX loop
2. Standardized startup and TX logging with dlog/banner/kv
3. Corrected telemetry packet-size debug logging
4. Added clearer comments for learning and stage-demo readability
5. Kept transport behavior the same to avoid destabilizing the working baseline
"""

from __future__ import annotations

import base64
import json
import random
import select
import time
import zlib
from typing import Any

import serial

from common.demo_log import dlog, banner, kv
from common.telemetry import sample_telemetry
from ccsds.frame import build_frame, canonical_json_bytes
from crypto.aes_gcm import encrypt
from crypto.key_manager import KeyManager
from crypto.mldsa_signatures import sign, b64e

# ---------------------------------------------------------------------
# Serial / link settings
# ---------------------------------------------------------------------
SERIAL_PORT = "/dev/ttyACM0"
BAUD_RATE = 115200

# ---------------------------------------------------------------------
# Mission / packet identity
# ---------------------------------------------------------------------
SPACECRAFT_ID = "AegisLEO-SAT-1"
APID = 100

# ---------------------------------------------------------------------
# Chunking / pacing
# ---------------------------------------------------------------------
SESSION_INIT_CHUNK_SIZE = 220
TELEMETRY_CHUNK_SIZE = 140

SESSION_INIT_CHUNK_DELAY_SECONDS = 0.80
TELEMETRY_CHUNK_DELAY_SECONDS = 0.08

ACK_WAIT_SECONDS = 15.0
MAX_RETRIES = 6

# ---------------------------------------------------------------------
# Framing markers used over the serial link
# ---------------------------------------------------------------------
FRAME_START = b"\x7E"
FRAME_END = b"\x7F"

# ---------------------------------------------------------------------
# Debug flags
# ---------------------------------------------------------------------
DEBUG_TX_CHUNKS = False
DEBUG_ACKS = True
DEBUG_BAD_FRAMES = True
DEBUG_PACKET_SIZES = True

# ---------------------------------------------------------------------
# Compression / crypto config
# ---------------------------------------------------------------------
COMPRESSION_LEVEL = 6
MLDSA_ALGORITHM = "ML-DSA-65"

SATELLITE_MLDSA_SECRET_KEY_PATH = "keys/satellite_mldsa_secret.key"
RECEIVER_KEM_PUBLIC_KEY_PATH = "dev_secrets/satellite/receiver_kem_public.key"


def packet_to_base64_with_stats(packet: dict[str, Any]) -> tuple[str, int, int, int]:
    """
    Convert a packet dict into:
      1. compact JSON bytes
      2. zlib-compressed bytes
      3. base64 text for chunk transport

    Returns:
        (encoded_text, raw_len, compressed_len, encoded_len)
    """
    raw = json.dumps(packet, separators=(",", ":")).encode("utf-8")
    compressed = zlib.compress(raw, level=COMPRESSION_LEVEL)
    encoded = base64.b64encode(compressed).decode("utf-8")
    return encoded, len(raw), len(compressed), len(encoded)


def split_chunks(text: str, chunk_size: int) -> list[str]:
    """Split a long string into fixed-size transport fragments."""
    return [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]


def make_chunk_packets(
    chunk_type: str,
    session_id: str,
    encoded_payload: str,
    chunk_size: int,
    message_id: int | None = None,
) -> list[dict[str, Any]]:
    """
    Wrap a base64 payload into chunk packets for transport.

    Packet fields:
      t   = chunk type ("si" for session init, "tc" for telemetry chunk)
      sid = session id
      i   = chunk index
      n   = total chunk count
      d   = data fragment
      c   = CRC32 of the fragment
      mid = message id (used for telemetry, omitted for session init)
    """
    fragments = split_chunks(encoded_payload, chunk_size)
    total = len(fragments)

    packets: list[dict[str, Any]] = []
    for idx, frag in enumerate(fragments):
        frag_crc = zlib.crc32(frag.encode("utf-8")) & 0xFFFFFFFF

        pkt: dict[str, Any] = {
            "t": chunk_type,
            "sid": session_id,
            "i": idx,
            "n": total,
            "d": frag,
            "c": frag_crc,
        }

        if message_id is not None:
            pkt["mid"] = message_id

        packets.append(pkt)

    return packets


def write_transport_packet(ser: serial.Serial, pkt: dict[str, Any]) -> None:
    """
    Send one transport packet using the framing the receiver expects.

    Wire format:
        [FRAME_START][LEN:4][PAYLOAD][FRAME_END]
    """
    payload = json.dumps(pkt, separators=(",", ":")).encode("utf-8")
    length = len(payload).to_bytes(4, "big")
    wire = FRAME_START + length + payload + FRAME_END
    ser.write(wire)
    ser.flush()

    # Tiny pause to reduce back-to-back serial flooding.
    time.sleep(0.02)


def send_chunk_packets(
    ser: serial.Serial,
    packets: list[dict[str, Any]],
    delay_seconds: float,
) -> None:
    """
    Send transport chunks one at a time with pacing.

    Why pacing matters:
    - LoRa is slow and half-duplex
    - The receiver needs breathing room for chunk reassembly
    - Overdriving the line causes retries, NACK storms, and sadness
    """
    total = len(packets)

    for idx, pkt in enumerate(packets):
        write_transport_packet(ser, pkt)

        if DEBUG_TX_CHUNKS:
            dlog(
                "SAT",
                "CHUNK_TX",
                "Transport chunk sent",
                t=pkt["t"],
                sid=pkt["sid"],
                mid=pkt.get("mid"),
                idx=f"{idx + 1}/{total}",
            )

        # Telemetry gets gentler pacing than session init because it is
        # the repeated data path and can otherwise overwhelm RX.
        if pkt["t"] == "tc":
            # Brief processing gap every few telemetry chunks.
            if idx > 0 and idx % 5 == 0:
                time.sleep(0.25)

            time.sleep((delay_seconds * 2.5) + random.uniform(0.005, 0.02))
        else:
            time.sleep(delay_seconds + random.uniform(0.005, 0.02))


def extract_framed_packets(buffer: bytearray) -> list[bytes]:
    """
    Extract complete framed packets from the receive buffer.

    Expected frame format:
        [FRAME_START][LEN:4][PAYLOAD][FRAME_END]

    This is used on the transmitter side to parse ACK/NACK control traffic
    coming back from the ground station.
    """
    frames: list[bytes] = []

    while True:
        start = buffer.find(FRAME_START)

        if start == -1:
            buffer.clear()
            break

        if start > 0:
            del buffer[:start]

        if len(buffer) < 5:
            break

        if buffer[0:1] != FRAME_START:
            del buffer[0]
            continue

        payload_len = int.from_bytes(buffer[1:5], "big")

        if payload_len <= 0 or payload_len > 4096:
            if DEBUG_BAD_FRAMES:
                dlog("SAT", "WARN", "Invalid frame length while resyncing", payload_len=payload_len)
            del buffer[0]
            continue

        total_len = 1 + 4 + payload_len + 1

        if len(buffer) < total_len:
            break

        payload = bytes(buffer[5:5 + payload_len])
        end_marker = buffer[5 + payload_len:5 + payload_len + 1]

        if end_marker != FRAME_END:
            if DEBUG_BAD_FRAMES:
                dlog("SAT", "WARN", "Bad frame end marker while resyncing", end_marker=repr(end_marker))
            del buffer[0]
            continue

        del buffer[:total_len]
        frames.append(payload)

    return frames


def read_control_packet(ser: serial.Serial, timeout_seconds: float) -> dict[str, Any] | None:
    """
    Read one ACK/NACK control packet using framed serial input.
    """
    end_time = time.time() + timeout_seconds
    rx_buffer = bytearray()

    while time.time() < end_time:
        ready, _, _ = select.select([ser.fileno()], [], [], 0.2)
        if not ready:
            continue

        raw = ser.read(512)
        if not raw:
            continue

        rx_buffer.extend(raw)
        frames = extract_framed_packets(rx_buffer)

        for frame_bytes in frames:
            try:
                text = frame_bytes.decode("utf-8").strip()
                if not text:
                    continue
                pkt = json.loads(text)
            except UnicodeDecodeError:
                if DEBUG_BAD_FRAMES:
                    dlog("SAT", "WARN", "Dropped non-UTF8 control frame", preview=repr(frame_bytes[:80]))
                continue
            except json.JSONDecodeError:
                if DEBUG_BAD_FRAMES:
                    dlog("SAT", "WARN", "Dropped invalid JSON control frame", preview=repr(frame_bytes[:80]))
                continue

            if pkt.get("t") in {"ack", "nack"}:
                return pkt

    return None


def resend_missing_chunks(
    ser: serial.Serial,
    pending_chunks: list[dict[str, Any]],
    missing: list[int],
    delay_seconds: float,
) -> None:
    """
    Resend only the missing chunks if the receiver told us which ones it lacks.
    If the missing list is empty or unusable, resend the full set.
    """
    resend = [pkt for pkt in pending_chunks if pkt["i"] in missing]
    if not resend:
        resend = pending_chunks

    send_chunk_packets(ser, resend, delay_seconds)


def control_matches_session(control: dict[str, Any], session_id: str, message_id: int | None) -> bool:
    """
    Validate that a returned ACK/NACK belongs to this session and message.
    """
    if control.get("sid") != session_id:
        return False

    control_mid = control.get("mid")
    if message_id is None:
        return control_mid is None

    return control_mid == message_id


def wait_for_ack_or_nack(
    ser: serial.Serial,
    session_id: str,
    message_id: int | None,
    pending_chunks: list[dict[str, Any]],
    resend_delay_seconds: float,
) -> bool:
    """
    Wait for ACK/NACK and selectively recover missing chunks.

    Behavior differs slightly by message type:
    - session_init: quieter, listen-first recovery loop
    - telemetry: simpler retry loop
    """

    # -------------------------------------------------------------
    # SESSION INIT PATH
    # -------------------------------------------------------------
    if message_id is None:
        session_listen_cycles = 16
        seen_nack = False

        for cycle in range(1, session_listen_cycles + 1):
            control = read_control_packet(ser, ACK_WAIT_SECONDS)

            if control is not None and DEBUG_ACKS:
                dlog("SAT", "CTRL_RX", "Received control packet", pkt=control)

            if control is None:
                dlog(
                    "SAT",
                    "ACK_WAIT",
                    "Session-init quiet timeout",
                    sid=session_id,
                    cycle=f"{cycle}/{session_listen_cycles}",
                )

                # Rare nudge resends before the first valid NACK.
                if not seen_nack and cycle in {6, 10}:
                    dlog("SAT", "RECOVERY", "Pre-NACK resend-all burst", sid=session_id)
                    time.sleep(2.5)
                    send_chunk_packets(ser, pending_chunks, resend_delay_seconds)
                    time.sleep(2.5)

                continue

            if not control_matches_session(control, session_id, message_id):
                if DEBUG_ACKS:
                    dlog(
                        "SAT",
                        "CTRL_IGNORE",
                        "Ignoring control for different session/message",
                        sid=control.get("sid"),
                        mid=control.get("mid"),
                    )
                continue

            control_type = control.get("t")

            if control_type == "ack":
                dlog("SAT", "ACK", "Session-init acknowledged", sid=session_id)
                return True

            if control_type == "nack":
                missing = control.get("m", [])
                dlog(
                    "SAT",
                    "NACK",
                    "Session-init missing chunks reported",
                    sid=session_id,
                    missing=missing,
                    cycle=f"{cycle}/{session_listen_cycles}",
                )

                seen_nack = True
                time.sleep(0.5)
                resend_missing_chunks(
                    ser=ser,
                    pending_chunks=pending_chunks,
                    missing=missing,
                    delay_seconds=resend_delay_seconds,
                )
                time.sleep(4.0)
                continue

        return False

    # -------------------------------------------------------------
    # TELEMETRY PATH
    # -------------------------------------------------------------
    for attempt in range(1, MAX_RETRIES + 1):
        control = read_control_packet(ser, ACK_WAIT_SECONDS)

        if control is not None and DEBUG_ACKS:
            dlog("SAT", "CTRL_RX", "Received control packet", pkt=control)

        if control is None:
            dlog(
                "SAT",
                "ACK_WAIT",
                "Telemetry ACK timeout",
                sid=session_id,
                mid=message_id,
                attempt=f"{attempt}/{MAX_RETRIES}",
            )
            time.sleep(1.0)
            send_chunk_packets(ser, pending_chunks, resend_delay_seconds)
            time.sleep(1.0)
            continue

        if not control_matches_session(control, session_id, message_id):
            if DEBUG_ACKS:
                dlog(
                    "SAT",
                    "CTRL_IGNORE",
                    "Ignoring control for different session/message",
                    sid=control.get("sid"),
                    mid=control.get("mid"),
                )
            continue

        if control.get("t") == "ack":
            dlog("SAT", "ACK", "Telemetry acknowledged", sid=session_id, mid=message_id)
            return True

        if control.get("t") == "nack":
            missing = control.get("m", [])
            dlog(
                "SAT",
                "NACK",
                "Telemetry missing chunks reported",
                sid=session_id,
                mid=message_id,
                missing=missing,
            )
            time.sleep(0.5)
            resend_missing_chunks(
                ser=ser,
                pending_chunks=pending_chunks,
                missing=missing,
                delay_seconds=resend_delay_seconds,
            )
            time.sleep(1.0)

    return False


# ---------------------------------------------------------------------
# Load long-term keys and initialize secure session
# ---------------------------------------------------------------------
with open(SATELLITE_MLDSA_SECRET_KEY_PATH, "rb") as f:
    MLDSA_SECRET_KEY = f.read()

with open(RECEIVER_KEM_PUBLIC_KEY_PATH, "rb") as f:
    RECEIVER_KEM_PUBLIC_KEY = f.read()

key_manager = KeyManager()
initiator_handshake = key_manager.create_initiator_session(RECEIVER_KEM_PUBLIC_KEY)
session = initiator_handshake.session
kem_ciphertext = initiator_handshake.kem_ciphertext

# ---------------------------------------------------------------------
# Open serial transport
# ---------------------------------------------------------------------
ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=0.2)
sequence = 1

banner("AegisLEO Secure Satellite Telemetry Transmitter")
kv("Serial port", SERIAL_PORT)
kv("Baud rate", BAUD_RATE)
kv("Spacecraft", SPACECRAFT_ID)
kv("Session ID", session.session_id)
kv("KEM alg", key_manager.algorithm)
print("Press Ctrl+C to stop.", flush=True)

# ---------------------------------------------------------------------
# Build and send signed session-init packet
# ---------------------------------------------------------------------
session_init_core = {
    "type": "session_init",
    "spacecraft_id": SPACECRAFT_ID,
    "session_id": session.session_id,
    "kem_ciphertext": b64e(kem_ciphertext),
}

session_init_signature = sign(
    canonical_json_bytes(session_init_core),
    MLDSA_SECRET_KEY,
    algorithm=MLDSA_ALGORITHM,
)

session_init_packet = {
    **session_init_core,
    "signature": b64e(session_init_signature),
}

(
    session_init_b64,
    session_init_raw_len,
    session_init_comp_len,
    session_init_enc_len,
) = packet_to_base64_with_stats(session_init_packet)

session_init_chunks = make_chunk_packets(
    chunk_type="si",
    session_id=session.session_id,
    encoded_payload=session_init_b64,
    chunk_size=SESSION_INIT_CHUNK_SIZE,
    message_id=None,
)

if DEBUG_PACKET_SIZES:
    dlog(
        "SAT",
        "SESSION_INIT_PREP",
        "Prepared secure session-init packet",
        raw=session_init_raw_len,
        compressed=session_init_comp_len,
        encoded=session_init_enc_len,
        chunks=len(session_init_chunks),
        chunk_size=SESSION_INIT_CHUNK_SIZE,
    )

send_chunk_packets(ser, session_init_chunks, SESSION_INIT_CHUNK_DELAY_SECONDS)

dlog(
    "SAT",
    "SESSION_INIT_TX",
    "Sent session-init to ground station",
    session=session.session_id,
    chunks=len(session_init_chunks),
)

# Give the half-duplex link time to flip from TX to RX cleanly.
time.sleep(2.5)

session_init_ok = wait_for_ack_or_nack(
    ser=ser,
    session_id=session.session_id,
    message_id=None,
    pending_chunks=session_init_chunks,
    resend_delay_seconds=SESSION_INIT_CHUNK_DELAY_SECONDS,
)

if not session_init_ok:
    dlog("SAT", "FATAL", "Session-init delivery failed after retries", session=session.session_id)
    raise SystemExit(1)

dlog("SAT", "SESSION_READY", "Session-init acknowledged by ground station", session=session.session_id)
time.sleep(1)

# ---------------------------------------------------------------------
# Main telemetry transmit loop
# ---------------------------------------------------------------------
while True:
    # Build one human-readable telemetry object for the demo and for the packet.
    telemetry = sample_telemetry(sequence)

    payload = {
        "temp_c": telemetry.temperature_c,
        "bus_v": telemetry.bus_v,
        "bus_i": telemetry.bus_i,
        "state": telemetry.mode,
        "battery_pct": telemetry.battery_pct,
        "latitude": telemetry.latitude,
        "longitude": telemetry.longitude,
        "altitude_km": telemetry.altitude_km,
    }

    dlog(
        "SAT",
        "TELEMETRY_BUILD",
        "Generated telemetry sample",
        seq=telemetry.seq,
        summary=telemetry.summary(),
    )

    # Build CCSDS-style application frame before encryption.
    frame = build_frame(
        spacecraft_id=SPACECRAFT_ID,
        sequence=sequence,
        apid=APID,
        payload=payload,
    )

    frame_bytes = canonical_json_bytes(frame)

    # Encrypt the frame payload using the active session AES key.
    encrypted = encrypt(
        frame_bytes,
        session.aes_key,
        aad=SPACECRAFT_ID.encode("utf-8"),
    )

    # Sign the packet core so the receiver can validate authenticity
    # before attempting decryption.
    packet_core = {
        "type": "telemetry",
        "spacecraft_id": SPACECRAFT_ID,
        "session_id": session.session_id,
        "nonce": b64e(encrypted["nonce"]),
        "ciphertext": b64e(encrypted["ciphertext"]),
    }

    telemetry_signature = sign(
        canonical_json_bytes(packet_core),
        MLDSA_SECRET_KEY,
        algorithm=MLDSA_ALGORITHM,
    )

    transmitted_packet = {
        **packet_core,
        "signature": b64e(telemetry_signature),
    }

    telemetry_b64, telemetry_raw_len, telemetry_comp_len, telemetry_enc_len = (
        packet_to_base64_with_stats(transmitted_packet)
    )

    telemetry_chunks = make_chunk_packets(
        chunk_type="tc",
        session_id=session.session_id,
        encoded_payload=telemetry_b64,
        chunk_size=TELEMETRY_CHUNK_SIZE,
        message_id=sequence,
    )

    send_chunk_packets(ser, telemetry_chunks, TELEMETRY_CHUNK_DELAY_SECONDS)

    if DEBUG_PACKET_SIZES:
        dlog(
            "SAT",
            "TELEMETRY_TX",
            "Sent secure telemetry packet",
            session=session.session_id,
            seq=sequence,
            chunks=len(telemetry_chunks),
            raw=telemetry_raw_len,
            compressed=telemetry_comp_len,
            encoded=telemetry_enc_len,
            chunk_size=TELEMETRY_CHUNK_SIZE,
        )

    # Short pause before listening for ACK/NACK response.
    time.sleep(1.0)

    delivery_ok = wait_for_ack_or_nack(
        ser=ser,
        session_id=session.session_id,
        message_id=sequence,
        pending_chunks=telemetry_chunks,
        resend_delay_seconds=TELEMETRY_CHUNK_DELAY_SECONDS,
    )

    if not delivery_ok:
        dlog("SAT", "DELIVERY_FAIL", "Telemetry delivery failed after retries", seq=sequence)
    else:
        dlog("SAT", "DELIVERY_OK", "Telemetry acknowledged by ground station", seq=sequence)

    sequence += 1
    time.sleep(3)