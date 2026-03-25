"""
AegisLEO Ground Station Secure Receiver

Created by: Jamie Grunewald
Date: 2026-03-24
Version: v0.6.2

Purpose
-------
This script runs on the ground station and listens for incoming
secure telemetry packets from the satellite node.

Protocol
--------
This receiver supports a two-phase protocol:

1. session_init
   - sent once by the satellite
   - contains session_id + kem_ciphertext
   - receiver derives and stores the session AES key

2. telemetry
   - sent repeatedly after session_init
   - contains session_id + nonce + ciphertext
   - receiver decrypts using the stored session AES key

Why this version matters
------------------------
LoRa serial bridges do not always preserve newline or packet boundaries.
So this receiver uses a rolling text buffer and incremental JSON decoding
to reconstruct complete JSON objects from partial serial chunks.

This version also adds temporary debug output so we can see:
- raw chunks arriving from serial
- whether the buffer is growing but never forming valid JSON
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import serial

from ccsds.frame import canonical_json_bytes, parse_json_bytes
from crypto.aes_gcm import decrypt
from crypto.key_manager import KeyManager
from crypto.mldsa_signatures import verify, b64d
from groundstation.replay_window import ReplayWindow
from models.runtime_detector import RuntimeDetector


# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------
SERIAL_PORT = "/dev/serial/by-id/usb-1a86_USB_Single_Serial_5AAF186928-if00"
BAUD_RATE = 115200

MLDSA_ALGORITHM = "ML-DSA-65"

SATELLITE_MLDSA_PUBLIC_KEY_PATH = "keys/satellite_mldsa_public.key"
RECEIVER_KEM_PRIVATE_KEY_PATH = "dev_secrets/groundstation/receiver_kem_private.key"

# Temporary debug controls
DEBUG_SERIAL = True
DEBUG_BUFFER = True


# ---------------------------------------------------------------------
# Load key material
# ---------------------------------------------------------------------
with open(SATELLITE_MLDSA_PUBLIC_KEY_PATH, "rb") as f:
    SATELLITE_MLDSA_PUBLIC_KEY = f.read()

with open(RECEIVER_KEM_PRIVATE_KEY_PATH, "rb") as f:
    RECEIVER_KEM_PRIVATE_KEY = f.read()


# ---------------------------------------------------------------------
# Runtime objects
# ---------------------------------------------------------------------
ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)

key_manager = KeyManager()
detector = RuntimeDetector()

sessions: dict[str, object] = {}
replay_windows: dict[str, ReplayWindow] = {}

decoder = json.JSONDecoder()

print("Ground station secure receiver online")
print(f"Serial port: {SERIAL_PORT}")
print(f"Baud rate  : {BAUD_RATE}")
print(f"KEM alg    : {key_manager.algorithm}")
print("Press Ctrl+C to stop.")


# ---------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------
def pretty_time(epoch: int) -> str:
    """
    Convert a Unix timestamp into a human-readable UTC string.
    """
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def extract_next_json(buffer: str) -> tuple[dict | None, str]:
    """
    Attempt to extract one complete JSON object from a text buffer.

    Returns
    -------
    tuple[dict | None, str]
        - parsed JSON object if successful, else None
        - remaining buffer
    """
    start = buffer.find("{")
    if start == -1:
        return None, ""

    candidate = buffer[start:]

    try:
        packet, end_idx = decoder.raw_decode(candidate)
        remaining = candidate[end_idx:]
        return packet, remaining
    except json.JSONDecodeError:
        return None, candidate


# ---------------------------------------------------------------------
# Main receive loop
# ---------------------------------------------------------------------
buffer = ""

while True:
    chunk = ser.read(1024)

    if not chunk:
        continue

    if DEBUG_SERIAL:
        print(f"[DEBUG] RAW CHUNK: {repr(chunk[:120])}")

    buffer += chunk.decode("utf-8", errors="ignore")

    if DEBUG_BUFFER and len(buffer) > 300:
        print(f"[DEBUG] BUFFER LEN: {len(buffer)}")

    while True:
        packet, buffer = extract_next_json(buffer)

        if packet is None:
            break

        try:
            packet_type = packet.get("type")

            # ---------------------------------------------------------
            # Step 1: Handle session_init packets
            # ---------------------------------------------------------
            if packet_type == "session_init":
                packet_core = {
                    "type": packet["type"],
                    "spacecraft_id": packet["spacecraft_id"],
                    "session_id": packet["session_id"],
                    "kem_ciphertext": packet["kem_ciphertext"],
                }

                is_valid_signature = verify(
                    canonical_json_bytes(packet_core),
                    b64d(packet["signature"]),
                    SATELLITE_MLDSA_PUBLIC_KEY,
                    algorithm=MLDSA_ALGORITHM,
                )

                if not is_valid_signature:
                    print("[GROUND] REJECTED: session_init signature verification failed")
                    continue

                session_id = packet["session_id"]

                if session_id in sessions:
                    print(f"[GROUND] INFO: session already exists ({session_id})")
                    continue

                print(f"[GROUND] Received session_init: {session_id}")

                session = key_manager.create_receiver_session(
                    kem_ciphertext=b64d(packet["kem_ciphertext"]),
                    receiver_private_key=RECEIVER_KEM_PRIVATE_KEY,
                    session_id=session_id,
                )

                sessions[session_id] = session
                replay_windows[session_id] = ReplayWindow(window_size=64)

                print(f"[GROUND] Session established: {session_id}")
                continue

            # ---------------------------------------------------------
            # Step 2: Handle telemetry packets
            # ---------------------------------------------------------
            if packet_type != "telemetry":
                print(f"[GROUND] WARN: unknown packet type: {packet_type}")
                continue

            packet_core = {
                "type": packet["type"],
                "spacecraft_id": packet["spacecraft_id"],
                "session_id": packet["session_id"],
                "nonce": packet["nonce"],
                "ciphertext": packet["ciphertext"],
            }

            is_valid_signature = verify(
                canonical_json_bytes(packet_core),
                b64d(packet["signature"]),
                SATELLITE_MLDSA_PUBLIC_KEY,
                algorithm=MLDSA_ALGORITHM,
            )

            if not is_valid_signature:
                print("[GROUND] REJECTED: telemetry signature verification failed")
                continue

            session_id = packet["session_id"]

            if session_id not in sessions:
                print(f"[GROUND] WARN: telemetry received before session established ({session_id})")
                continue

            session = sessions[session_id]
            replay_window = replay_windows[session_id]

            if session.is_expired():
                print(f"[GROUND] REJECTED: session expired ({session_id})")
                continue

            # ---------------------------------------------------------
            # Step 3: Decrypt telemetry payload
            # ---------------------------------------------------------
            plaintext = decrypt(
                b64d(packet["nonce"]),
                b64d(packet["ciphertext"]),
                session.aes_key,
                aad=b"AegisLEO-SAT-1")
                #aad=packet["spacecraft_id"].encode("utf-8"),
            )

            # ---------------------------------------------------------
            # Step 4: Parse decrypted frame
            # ---------------------------------------------------------
            frame = parse_json_bytes(plaintext)

            # ---------------------------------------------------------
            # Step 5: Replay protection
            # ---------------------------------------------------------
            sequence = int(frame["sequence"])

            decision = replay_window.check(sequence)
            if not decision.accepted:
                print(
                    f"[GROUND] REJECTED: replay protection blocked packet "
                    f"(session={session_id}, seq={sequence}, reason={decision.reason})"
                )
                continue

            previous_max = replay_window.max_seq
            replay_window.record(sequence)

            # ---------------------------------------------------------
            # Step 6: Compute gap
            # ---------------------------------------------------------
            gap = 0
            if previous_max != -1 and sequence > previous_max + 1:
                gap = sequence - previous_max - 1

            # ---------------------------------------------------------
            # Step 7: Run anomaly detection
            # ---------------------------------------------------------
            detection = detector.detect(frame)

            # ---------------------------------------------------------
            # Step 8: Print operator view
            # ---------------------------------------------------------
            payload = frame["payload"]

            print("=" * 72)
            print("AegisLEO Secure Telemetry Packet")
            print(f"Spacecraft : {frame['spacecraft_id']}")
            print(f"Session ID : {session_id}")
            print(f"Timestamp  : {pretty_time(frame['timestamp'])}")
            print(f"APID       : {frame['apid']}")
            print(f"Sequence   : {sequence}")
            print(f"Gap        : {gap}")
            print(f"Replay     : ACCEPTED ({decision.reason})")
            print("Crypto     : signature=VALID, session=ACTIVE, decrypt=SUCCESS")

            if detection.is_anomalous:
                print(
                    f"ML         : ANOMALY "
                    f"(score={detection.score}, reasons={detection.reasons})"
                )
            else:
                print(f"ML         : nominal (score={detection.score})")

            print(
                f"Payload    : temp_c={payload['temp_c']} "
                f"bus_v={payload['bus_v']} "
                f"bus_i={payload['bus_i']} "
                f"state={payload['state']}"
            )
            print("=" * 72)

        except Exception as exc:
            print(f"[GROUND] WARN: packet processing failed: {exc}")