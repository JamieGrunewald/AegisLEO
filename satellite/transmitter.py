"""
AegisLEO Secure Satellite Telemetry Transmitter
Transport-Hardened RF Version with Selective session_init Recovery

Created by: Jamie Grunewald
Updated by: OpenAI ChatGPT
Date: 2026-03-25
Version: v0.11.4

v0.11.2 patch notes
-------------------
1. stronger control-plane quiet windows
2. larger control read window
3. control RX logging added
4. initial burst pacing cleaned up
5. session_init retry pacing tuned for half-duplex link behavior
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

SERIAL_PORT = "/dev/ttyACM0"
BAUD_RATE = 115200

SPACECRAFT_ID = "AegisLEO-SAT-1"
APID = 100

SESSION_INIT_CHUNK_SIZE = 220
TELEMETRY_CHUNK_SIZE = 180

SESSION_INIT_CHUNK_DELAY_SECONDS = 0.45
TELEMETRY_CHUNK_DELAY_SECONDS = 0.08

ACK_WAIT_SECONDS = 15.0
MAX_RETRIES = 6

FRAME_START = b"\x7E"
FRAME_END = b"\x7F"

MAX_CONTROL_FRAME_JSON_BYTES = 512

DEBUG_TX_CHUNKS = False
DEBUG_ACKS = True
DEBUG_BAD_FRAMES = True
DEBUG_PACKET_SIZES = True

COMPRESSION_LEVEL = 6

MLDSA_ALGORITHM = "ML-DSA-65"

SATELLITE_MLDSA_SECRET_KEY_PATH = "keys/satellite_mldsa_secret.key"
RECEIVER_KEM_PUBLIC_KEY_PATH = "dev_secrets/satellite/receiver_kem_public.key"


def packet_to_base64_with_stats(packet: dict[str, Any]) -> tuple[str, int, int, int]:
    raw = json.dumps(packet, separators=(",", ":")).encode("utf-8")
    compressed = zlib.compress(raw, level=COMPRESSION_LEVEL)
    encoded = base64.b64encode(compressed).decode("utf-8")
    return encoded, len(raw), len(compressed), len(encoded)


def split_chunks(text: str, chunk_size: int) -> list[str]:
    return [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]


def make_chunk_packets(
    chunk_type: str,
    session_id: str,
    encoded_payload: str,
    chunk_size: int,
    message_id: int | None = None,
) -> list[dict[str, Any]]:
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
    payload = json.dumps(pkt, separators=(",", ":")).encode("utf-8")
    wire = FRAME_START + payload + FRAME_END
    ser.write(wire)
    ser.flush()


def send_chunk_packets(
    ser: serial.Serial,
    packets: list[dict[str, Any]],
    delay_seconds: float,
) -> None:
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
                    print(f"[SAT] WARN: non-UTF8 control frame dropped: {frame_bytes[:80]!r}")
                continue
            except json.JSONDecodeError:
                if DEBUG_BAD_FRAMES:
                    print(f"[SAT] WARN: invalid control frame: {frame_bytes[:80]!r}")
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
    resend = [pkt for pkt in pending_chunks if pkt["i"] in missing]
    if not resend:
        resend = pending_chunks
    send_chunk_packets(ser, resend, delay_seconds)


def control_matches_session(control: dict[str, Any], session_id: str, message_id: int | None) -> bool:
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
    Improved session_init recovery logic:

    Key behavior:
    - Listen FIRST
    - After first NACK -> switch to selective-only mode
    - Never resend full burst again after NACK
    """

    # -------------------------------------------------------------
    # SESSION INIT: selective-lock recovery mode
    # -------------------------------------------------------------
    if message_id is None:
        session_listen_cycles = 12
        seen_nack = False  # 🔥 critical new state

        for cycle in range(1, session_listen_cycles + 1):
            control = read_control_packet(ser, ACK_WAIT_SECONDS)

            if control is not None:
                print(f"[SAT][CTRL RX] {control}")

            # -----------------------------------------------------
            # NOTHING RECEIVED
            # -----------------------------------------------------
            if control is None:
                if DEBUG_ACKS:
                    print(
                        f"[SAT][ACK] session_init quiet timeout "
                        f"sid={session_id} cycle={cycle}/{session_listen_cycles}"
                    )

                # 🚫 BEFORE NACK: occasional resend-all (rare)
                if not seen_nack and cycle % 4 == 0:
                    print("[SAT] pre-NACK recovery burst (rare resend-all)")
                    time.sleep(2.0)
                    send_chunk_packets(ser, pending_chunks, resend_delay_seconds)
                    time.sleep(2.0)

                # ✅ AFTER NACK: DO NOTHING (listen only)
                continue

            # -----------------------------------------------------
            # FILTER WRONG SESSION
            # -----------------------------------------------------
            if not control_matches_session(control, session_id, message_id):
                if DEBUG_ACKS:
                    print(
                        f"[SAT][CTRL RX] ignoring control for sid={control.get('sid')} "
                        f"mid={control.get('mid')}"
                    )
                continue

            control_type = control.get("t")

            # -----------------------------------------------------
            # ACK
            # -----------------------------------------------------
            if control_type == "ack":
                print(f"[SAT][ACK] received sid={session_id}")
                return True

            # -----------------------------------------------------
            # NACK (THIS IS THE IMPORTANT PATH)
            # -----------------------------------------------------
            if control_type == "nack":
                missing = control.get("m", [])

                print(
                    f"[SAT][NACK] sid={session_id} missing={missing} "
                    f"cycle={cycle}/{session_listen_cycles}"
                )

                # 🔥 lock into selective-only mode
                seen_nack = True

                # small pause so we don't collide with RX path
                time.sleep(0.5)

                # resend ONLY missing chunks
                resend_missing_chunks(
                    ser,
                    pending_chunks,
                    missing,
                    resend_delay_seconds,
                )

                # bigger quiet window after resend
                time.sleep(2.0)

                continue

        return False

    # -------------------------------------------------------------
    # TELEMETRY: leave unchanged
    # -------------------------------------------------------------
    for attempt in range(1, MAX_RETRIES + 1):
        control = read_control_packet(ser, ACK_WAIT_SECONDS)

        if control is not None:
            print(f"[SAT][CTRL RX] {control}")

        if control is None:
            print(
                f"[SAT][ACK] timeout sid={session_id} mid={message_id} "
                f"attempt={attempt}/{MAX_RETRIES}"
            )

            time.sleep(1.0)
            send_chunk_packets(ser, pending_chunks, resend_delay_seconds)
            time.sleep(1.0)
            continue

        if not control_matches_session(control, session_id, message_id):
            continue

        if control.get("t") == "ack":
            print(f"[SAT][ACK] received sid={session_id} mid={message_id}")
            return True

        if control.get("t") == "nack":
            missing = control.get("m", [])
            print(f"[SAT][NACK] sid={session_id} mid={message_id} missing={missing}")

            time.sleep(0.5)
            resend_missing_chunks(ser, pending_chunks, missing, resend_delay_seconds)
            time.sleep(1.0)

    return False

with open(SATELLITE_MLDSA_SECRET_KEY_PATH, "rb") as f:
    MLDSA_SECRET_KEY = f.read()

with open(RECEIVER_KEM_PUBLIC_KEY_PATH, "rb") as f:
    RECEIVER_KEM_PUBLIC_KEY = f.read()

key_manager = KeyManager()

initiator_handshake = key_manager.create_initiator_session(RECEIVER_KEM_PUBLIC_KEY)
session = initiator_handshake.session
kem_ciphertext = initiator_handshake.kem_ciphertext

ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=0.2)
sequence = 1

print("Satellite secure transmitter online")
print(f"Serial port: {SERIAL_PORT}")
print(f"Baud rate  : {BAUD_RATE}")
print(f"Spacecraft : {SPACECRAFT_ID}")
print(f"Session ID : {session.session_id}")
print(f"KEM alg    : {key_manager.algorithm}")
print("Press Ctrl+C to stop.")

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
    print(
        f"[SAT] session_init sizes raw={session_init_raw_len} "
        f"compressed={session_init_comp_len} encoded={session_init_enc_len} "
        f"chunks={len(session_init_chunks)} chunk_size={SESSION_INIT_CHUNK_SIZE}"
    )

send_chunk_packets(ser, session_init_chunks, SESSION_INIT_CHUNK_DELAY_SECONDS)

print(
    f"[SAT] Sent session_init for session={session.session_id} "
    f"({len(session_init_chunks)} chunks)"
)

# Quiet window for control-plane response after the burst.
time.sleep(1.0)

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

while True:
    payload = {
        "temp_c": round(random.uniform(11.5, 15.5), 2),
        "bus_v": round(random.uniform(4.85, 5.15), 2),
        "bus_i": round(random.uniform(0.30, 0.65), 3),
        "state": random.choice(["NOMINAL", "SUNPOINT", "TX_WINDOW"]),
    }

    frame = build_frame(
        spacecraft_id=SPACECRAFT_ID,
        sequence=sequence,
        apid=APID,
        payload=payload,
    )

    frame_bytes = canonical_json_bytes(frame)

    encrypted = encrypt(
        frame_bytes,
        session.aes_key,
        aad=SPACECRAFT_ID.encode("utf-8"),
    )

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
        print(
            f"[SAT] TX secure packet "
            f"session={session.session_id} seq={sequence} "
            f"chunks={len(telemetry_chunks)} "
            f"raw={telemetry_raw_len} compressed={telemetry_comp_len} "
            f"encoded={telemetry_enc_len} chunk_size={TELEMETRY_CHUNK_SIZE} "
            f"payload={payload}"
        )

    time.sleep(1.0)

    delivery_ok = wait_for_ack_or_nack(
        ser=ser,
        session_id=session.session_id,
        message_id=sequence,
        pending_chunks=telemetry_chunks,
        resend_delay_seconds=TELEMETRY_CHUNK_DELAY_SECONDS,
    )

    if not delivery_ok:
        print(f"[SAT] ERROR: telemetry seq={sequence} failed after retries")

    sequence += 1
    time.sleep(3)