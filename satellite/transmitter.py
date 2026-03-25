"""
AegisLEO Secure Satellite Telemetry Transmitter
Transport-Hardened RF Version with ACK/NACK, Separate Control/Data Tuning, and Compression

Created by: Jamie Grunewald
Updated by: OpenAI ChatGPT
Date: 2026-03-25
Version: v0.11.0

Purpose
-------
This script runs on the satellite-side node and sends secure telemetry
to the ground station over the LoRa serial link.

Design goals for v2
-------------------
1. Larger chunks to reduce packet explosion
2. Separate tuning for session_init vs telemetry
3. Strict control-frame parsing
4. Better operator visibility into packet sizes
5. Cleaner retransmission logic
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

from ccsds.frame import build_frame, canonical_json_bytes
from crypto.aes_gcm import encrypt
from crypto.key_manager import KeyManager
from crypto.mldsa_signatures import sign, b64e


# ---------------------------------------------------------------------
# Serial / radio settings
# ---------------------------------------------------------------------
SERIAL_PORT = "/dev/ttyACM0"
BAUD_RATE = 115200

SPACECRAFT_ID = "AegisLEO-SAT-1"
APID = 100

# Separate transport tuning.
# session_init is large because of PQ material, so we give it its own pace.
SESSION_INIT_CHUNK_SIZE = 160
TELEMETRY_CHUNK_SIZE = 180

SESSION_INIT_CHUNK_DELAY_SECONDS = 0.18
TELEMETRY_CHUNK_DELAY_SECONDS = 0.08

# ACK/NACK timing
ACK_WAIT_SECONDS = 3.0
MAX_RETRIES = 4

# Transport frame markers
FRAME_START = b"\x7E"   # ~
FRAME_END = b"\x7F"

# Safety limit for inbound control packets
MAX_CONTROL_FRAME_JSON_BYTES = 512

# Debug controls
DEBUG_TX_CHUNKS = False
DEBUG_ACKS = True
DEBUG_BAD_FRAMES = True
DEBUG_PACKET_SIZES = True

# Compression level.
# Level 6 is a good compromise between size reduction and CPU effort.
COMPRESSION_LEVEL = 6


# ---------------------------------------------------------------------
# Crypto / key file settings
# ---------------------------------------------------------------------
MLDSA_ALGORITHM = "ML-DSA-65"

SATELLITE_MLDSA_SECRET_KEY_PATH = "keys/satellite_mldsa_secret.key"
RECEIVER_KEM_PUBLIC_KEY_PATH = "dev_secrets/satellite/receiver_kem_public.key"


# ---------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------
def packet_to_base64_with_stats(packet: dict[str, Any]) -> tuple[str, int, int, int]:
    """
    Convert one full logical packet into compact JSON bytes,
    compress it with zlib, then encode as base64 text.

    Returns
    -------
    encoded_text, raw_len, compressed_len, encoded_len
    """
    raw = json.dumps(packet, separators=(",", ":")).encode("utf-8")
    compressed = zlib.compress(raw, level=COMPRESSION_LEVEL)
    encoded = base64.b64encode(compressed).decode("utf-8")
    return encoded, len(raw), len(compressed), len(encoded)


def split_chunks(text: str, chunk_size: int) -> list[str]:
    """
    Split a string into fixed-size chunks.
    """
    return [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]


def make_chunk_packets(
    chunk_type: str,
    session_id: str,
    encoded_payload: str,
    chunk_size: int,
    message_id: int | None = None,
) -> list[dict[str, Any]]:
    """
    Wrap a long encoded payload in small transport chunk packets.

    Transport chunk packet fields
    -----------------------------
    t   -> chunk type ("si" for session_init, "tc" for telemetry)
    sid -> session ID
    mid -> logical message ID (used for telemetry, omitted for session_init)
    i   -> chunk index
    n   -> total chunk count
    d   -> data fragment
    """
    fragments = split_chunks(encoded_payload, chunk_size)
    total = len(fragments)

    packets: list[dict[str, Any]] = []
    for idx, frag in enumerate(fragments):
        pkt: dict[str, Any] = {
            "t": chunk_type,
            "sid": session_id,
            "i": idx,
            "n": total,
            "d": frag,
        }
        if message_id is not None:
            pkt["mid"] = message_id
        packets.append(pkt)

    return packets


def write_transport_packet(ser: serial.Serial, pkt: dict[str, Any]) -> None:
    """
    Send exactly one framed transport packet.

    Framing format
    --------------
    FRAME_START + JSON_BYTES + FRAME_END
    """
    payload = json.dumps(pkt, separators=(",", ":")).encode("utf-8")
    wire = FRAME_START + payload + FRAME_END
    ser.write(wire)
    ser.flush()


def send_chunk_packets(
    ser: serial.Serial,
    packets: list[dict[str, Any]],
    delay_seconds: float,
) -> None:
    """
    Send a whole set of transport chunks with a delay between each one.
    """
    total = len(packets)
    for idx, pkt in enumerate(packets):
        write_transport_packet(ser, pkt)
        if DEBUG_TX_CHUNKS:
            print(
                f"[SAT][CHUNK] t={pkt['t']} sid={pkt['sid']} "
                f"mid={pkt.get('mid')} idx={idx + 1}/{total}"
            )
        time.sleep(delay_seconds)


def extract_framed_packets(buffer: bytearray) -> list[bytes]:
    """
    Pull as many complete framed packets as possible out of a byte buffer.

    This is used for incoming ACK/NACK control packets.
    """
    frames: list[bytes] = []

    while True:
        start = buffer.find(FRAME_START)
        if start == -1:
            buffer.clear()
            break

        if start > 0:
            del buffer[:start]

        end = buffer.find(FRAME_END, 1)
        if end == -1:
            if len(buffer) > MAX_CONTROL_FRAME_JSON_BYTES + 2:
                del buffer[0]
            break

        frame = bytes(buffer[1:end])
        del buffer[:end + 1]

        if not frame:
            continue

        if len(frame) > MAX_CONTROL_FRAME_JSON_BYTES:
            if DEBUG_BAD_FRAMES:
                print(f"[SAT] WARN: oversized control frame dropped ({len(frame)} bytes)")
            continue

        frames.append(frame)

    return frames


def read_control_packet(ser: serial.Serial, timeout_seconds: float) -> dict[str, Any] | None:
    """
    Wait briefly for one framed ACK/NACK control packet.
    """
    end_time = time.time() + timeout_seconds
    rx_buffer = bytearray()

    while time.time() < end_time:
        ready, _, _ = select.select([ser.fileno()], [], [], 0.1)
        if not ready:
            continue

        raw = ser.read(256)
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
                    print(f"[SAT] WARN: non-UTF8 control frame dropped: {frame_bytes[:80]!r}")
                continue
            except json.JSONDecodeError:
                if DEBUG_BAD_FRAMES:
                    print(f"[SAT] WARN: invalid control frame: {frame_bytes[:80]!r}")
                continue

            if pkt.get("t") in {"ack", "nack"}:
                return pkt

    return None


def wait_for_ack_or_nack(
    ser: serial.Serial,
    session_id: str,
    message_id: int | None,
    pending_chunks: list[dict[str, Any]],
    resend_delay_seconds: float,
) -> bool:
    """
    Wait for ACK/NACK and handle retransmission.

    Policy
    ------
    - session_init (message_id is None):
      resend the whole message on timeout/NACK
    - telemetry:
      selectively resend missing chunk indexes when NACK arrives
    """
    for attempt in range(1, MAX_RETRIES + 1):
        control = read_control_packet(ser, ACK_WAIT_SECONDS)

        if control is None:
            if DEBUG_ACKS:
                print(
                    f"[SAT][ACK] timeout sid={session_id} mid={message_id} "
                    f"attempt={attempt}/{MAX_RETRIES}"
                )
            send_chunk_packets(ser, pending_chunks, resend_delay_seconds)
            continue

        if control.get("sid") != session_id:
            continue

        if control.get("mid") != message_id:
            continue

        control_type = control.get("t")

        if control_type == "ack":
            if DEBUG_ACKS:
                print(f"[SAT][ACK] received sid={session_id} mid={message_id}")
            return True

        if control_type == "nack":
            # session_init: resend whole thing
            if message_id is None:
                if DEBUG_ACKS:
                    print(
                        f"[SAT][NACK] session_init sid={session_id} "
                        f"attempt={attempt}/{MAX_RETRIES} -> resend all chunks"
                    )
                send_chunk_packets(ser, pending_chunks, resend_delay_seconds)
                continue

            # telemetry: resend only missing indexes
            missing = control.get("m", [])
            if DEBUG_ACKS:
                print(
                    f"[SAT][NACK] sid={session_id} mid={message_id} "
                    f"missing={missing} attempt={attempt}/{MAX_RETRIES}"
                )

            resend = [pkt for pkt in pending_chunks if pkt["i"] in missing]
            if not resend:
                resend = pending_chunks

            send_chunk_packets(ser, resend, resend_delay_seconds)
            continue

    return False


# ---------------------------------------------------------------------
# Load key material
# ---------------------------------------------------------------------
with open(SATELLITE_MLDSA_SECRET_KEY_PATH, "rb") as f:
    MLDSA_SECRET_KEY = f.read()

with open(RECEIVER_KEM_PUBLIC_KEY_PATH, "rb") as f:
    RECEIVER_KEM_PUBLIC_KEY = f.read()


# ---------------------------------------------------------------------
# Create PQ session at startup
# ---------------------------------------------------------------------
key_manager = KeyManager()

initiator_handshake = key_manager.create_initiator_session(
    RECEIVER_KEM_PUBLIC_KEY
)

session = initiator_handshake.session
kem_ciphertext = initiator_handshake.kem_ciphertext


# ---------------------------------------------------------------------
# Open serial interface to the LoRa radio
# ---------------------------------------------------------------------
ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=0.2)

# Logical telemetry sequence counter
sequence = 1


# ---------------------------------------------------------------------
# Startup banner
# ---------------------------------------------------------------------
print("Satellite secure transmitter online")
print(f"Serial port: {SERIAL_PORT}")
print(f"Baud rate  : {BAUD_RATE}")
print(f"Spacecraft : {SPACECRAFT_ID}")
print(f"Session ID : {session.session_id}")
print(f"KEM alg    : {key_manager.algorithm}")
print("Press Ctrl+C to stop.")


# ---------------------------------------------------------------------
# Send session_init once
# ---------------------------------------------------------------------
# Step 1: Build logical session_init core
session_init_core = {
    "type": "session_init",
    "spacecraft_id": SPACECRAFT_ID,
    "session_id": session.session_id,
    "kem_ciphertext": b64e(kem_ciphertext),
}

# Step 2: Sign the logical session_init packet
session_init_signature = sign(
    canonical_json_bytes(session_init_core),
    MLDSA_SECRET_KEY,
    algorithm=MLDSA_ALGORITHM,
)

# Step 3: Build final logical session_init packet
session_init_packet = {
    **session_init_core,
    "signature": b64e(session_init_signature),
}

# Step 4: Compress + base64 encode for chunking
(
    session_init_b64,
    session_init_raw_len,
    session_init_comp_len,
    session_init_enc_len,
) = packet_to_base64_with_stats(session_init_packet)

# Step 5: Split into RF-safe chunks with control-plane tuning
session_init_chunks = make_chunk_packets(
    chunk_type="si",
    session_id=session.session_id,
    encoded_payload=session_init_b64,
    chunk_size=SESSION_INIT_CHUNK_SIZE,
    message_id=None,
)

if DEBUG_PACKET_SIZES:
    print(
        f"[SAT] session_init sizes raw={session_init_raw_len} "
        f"compressed={session_init_comp_len} encoded={session_init_enc_len} "
        f"chunks={len(session_init_chunks)} chunk_size={SESSION_INIT_CHUNK_SIZE}"
    )

# Step 6: Send chunks
send_chunk_packets(ser, session_init_chunks, SESSION_INIT_CHUNK_DELAY_SECONDS)

print(
    f"[SAT] Sent session_init for session={session.session_id} "
    f"({len(session_init_chunks)} chunks)"
)

# Step 7: Wait for ACK/NACK
session_init_ok = wait_for_ack_or_nack(
    ser=ser,
    session_id=session.session_id,
    message_id=None,
    pending_chunks=session_init_chunks,
    resend_delay_seconds=SESSION_INIT_CHUNK_DELAY_SECONDS,
)

if not session_init_ok:
    print("[SAT] ERROR: session_init delivery failed after retries")
    raise SystemExit(1)

print("[SAT] session_init acknowledged by ground station")
time.sleep(1)


# ---------------------------------------------------------------------
# Main telemetry loop
# ---------------------------------------------------------------------
while True:
    # -------------------------------------------------------------
    # Step 1: Generate simulated telemetry
    # -------------------------------------------------------------
    payload = {
        "temp_c": round(random.uniform(11.5, 15.5), 2),
        "bus_v": round(random.uniform(4.85, 5.15), 2),
        "bus_i": round(random.uniform(0.30, 0.65), 3),
        "state": random.choice(["NOMINAL", "SUNPOINT", "TX_WINDOW"]),
    }

    # -------------------------------------------------------------
    # Step 2: Build CCSDS-inspired telemetry frame
    # -------------------------------------------------------------
    frame = build_frame(
        spacecraft_id=SPACECRAFT_ID,
        sequence=sequence,
        apid=APID,
        payload=payload,
    )

    # -------------------------------------------------------------
    # Step 3: Convert frame to deterministic bytes
    # -------------------------------------------------------------
    frame_bytes = canonical_json_bytes(frame)

    # -------------------------------------------------------------
    # Step 4: Encrypt frame using AES-GCM session key
    # -------------------------------------------------------------
    encrypted = encrypt(
        frame_bytes,
        session.aes_key,
        aad=SPACECRAFT_ID.encode("utf-8"),
    )

    # -------------------------------------------------------------
    # Step 5: Build logical telemetry packet
    # -------------------------------------------------------------
    packet_core = {
        "type": "telemetry",
        "spacecraft_id": SPACECRAFT_ID,
        "session_id": session.session_id,
        "nonce": b64e(encrypted["nonce"]),
        "ciphertext": b64e(encrypted["ciphertext"]),
    }

    # -------------------------------------------------------------
    # Step 6: Sign logical telemetry packet
    # -------------------------------------------------------------
    telemetry_signature = sign(
        canonical_json_bytes(packet_core),
        MLDSA_SECRET_KEY,
        algorithm=MLDSA_ALGORITHM,
    )

    transmitted_packet = {
        **packet_core,
        "signature": b64e(telemetry_signature),
    }

    # -------------------------------------------------------------
    # Step 7: Compress + base64 encode for chunking
    # -------------------------------------------------------------
    telemetry_b64, telemetry_raw_len, telemetry_comp_len, telemetry_enc_len = (
        packet_to_base64_with_stats(transmitted_packet)
    )

    # -------------------------------------------------------------
    # Step 8: Split telemetry into RF-safe chunks
    # -------------------------------------------------------------
    telemetry_chunks = make_chunk_packets(
        chunk_type="tc",
        session_id=session.session_id,
        encoded_payload=telemetry_b64,
        chunk_size=TELEMETRY_CHUNK_SIZE,
        message_id=sequence,
    )

    # -------------------------------------------------------------
    # Step 9: Send telemetry chunks
    # -------------------------------------------------------------
    send_chunk_packets(ser, telemetry_chunks, TELEMETRY_CHUNK_DELAY_SECONDS)

    if DEBUG_PACKET_SIZES:
        print(
            f"[SAT] TX secure packet "
            f"session={session.session_id} seq={sequence} "
            f"chunks={len(telemetry_chunks)} "
            f"raw={telemetry_raw_len} compressed={telemetry_comp_len} "
            f"encoded={telemetry_enc_len} chunk_size={TELEMETRY_CHUNK_SIZE} "
            f"payload={payload}"
        )
    else:
        print(
            f"[SAT] TX secure packet "
            f"session={session.session_id} seq={sequence} "
            f"chunks={len(telemetry_chunks)} payload={payload}"
        )

    # -------------------------------------------------------------
    # Step 10: Wait for ACK/NACK
    # -------------------------------------------------------------
    delivery_ok = wait_for_ack_or_nack(
        ser=ser,
        session_id=session.session_id,
        message_id=sequence,
        pending_chunks=telemetry_chunks,
        resend_delay_seconds=TELEMETRY_CHUNK_DELAY_SECONDS,
    )

    if not delivery_ok:
        print(f"[SAT] ERROR: telemetry seq={sequence} failed after retries")

    # -------------------------------------------------------------
    # Step 11: Move to next telemetry packet
    # -------------------------------------------------------------
    sequence += 1
    time.sleep(3)
