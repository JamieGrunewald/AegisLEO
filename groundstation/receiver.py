"""
AegisLEO Ground Station Secure Receiver

Created by: Jamie Grunewald
Date: 2026-03-24
Version: v0.6.1

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

# sessions[session_id] -> SessionState
sessions: dict[str, object] = {}

# replay_windows[session_id] -> ReplayWindow
replay_windows: dict[str, ReplayWindow] = {}

# Incremental JSON decoder for rebuilding packets from serial chunks
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
    Attempt to extract one complete JSON object from the front/middle of a text buffer.

    Why this exists
    ---------------
    The LoRa USB serial bridge may deliver:
    - partial JSON objects
    - multiple JSON objects in one chunk
    - extra junk before a valid '{'

    So we:
    1. find the first '{'
    2. try incremental JSON decoding from there
    3. if successful, return the parsed object + remaining buffer
    4. if incomplete, keep the buffer and wait for more bytes
    """
    start = buffer.find("{")
    if start == -1:
        # No JSON start found at all. Drop noise.
        return None, ""

    # Drop leading junk before the first JSON object.
    candidate = buffer[start:]

    try:
        packet, end_idx = decoder.raw_decode(candidate)
        remaining = candidate[end_idx:]
        return packet, remaining
    except json.JSONDecodeError:
        # Incomplete JSON object. Keep data from first '{' onward.
        return None, candidate


# ---------------------------------------------------------------------
# Main receive loop
# ---------------------------------------------------------------------
buffer = ""

while True:
    # Read a chunk of bytes from serial instead of using readline().
    # This is more reliable when the radio bridge splits packets.
    chunk = ser.read(1024)

    if not chunk:
        continue

    # Decode what we got into text and append to rolling buffer.
    buffer += chunk.decode("utf-8", errors="ignore")

    # Keep trying to peel complete JSON objects out of the buffer.
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
                aad=packet["spacecraft_id"].encode("utf-8"),
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
            # Step 6: Compute packet gap
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