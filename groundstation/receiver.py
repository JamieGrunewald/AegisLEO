"""
AegisLEO Ground Station Secure Receiver

Created by: Jamie Grunewald
Date: 2026-03-24
Version: v0.5.0

Purpose
-------
This script runs on the ground station and listens for incoming
secure telemetry packets from the satellite node.

What this receiver does
-----------------------
For every packet it receives, it will:

1. Read one line from the serial port
2. Parse the outer JSON wrapper
3. Verify the ML-DSA digital signature
4. Establish a PQ session on first sight of a new session_id
5. Decrypt the ciphertext using the session AES key
6. Parse the decrypted CCSDS-style telemetry frame
7. Check replay protection using a per-session ReplayWindow
8. Run lightweight anomaly detection
9. Print the packet contents in a readable format

Why this matters
----------------
This gives us a layered security pipeline:

- ML-DSA verifies the sender is trusted
- ML-KEM establishes a shared session key dynamically
- AES-GCM protects confidentiality and integrity
- ReplayWindow blocks duplicated / stale packets
- RuntimeDetector gives us a place to add ML anomaly detection

Important note
--------------
This version replaces the old hardcoded AES key with a session key
derived from ML-KEM via key_manager.py.
"""

from __future__ import annotations

# Standard library imports
import json
from datetime import datetime, UTC

# Third-party import for serial communication with the LoRa radio
import serial

# Project imports
from ccsds.frame import canonical_json_bytes, parse_json_bytes
from crypto.aes_gcm import decrypt
from crypto.key_manager import KeyManager
from crypto.mldsa_signatures import verify, b64d
from groundstation.replay_window import ReplayWindow
from models.runtime_detector import RuntimeDetector


# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------
# Serial device path for the LoRa receiver attached to the ground station.
SERIAL_PORT = "/dev/serial/by-id/usb-1a86_USB_Single_Serial_5AAF186928-if00"

# Baud rate for the serial link.
BAUD_RATE = 115200

# ML-DSA signing algorithm used for signature verification.
MLDSA_ALGORITHM = "ML-DSA-65"

# Path to the satellite's ML-DSA public key.
SATELLITE_MLDSA_PUBLIC_KEY_PATH = "keys/satellite_mldsa_public.key"

# Path to the ground station's ML-KEM private key.
# This key must remain ONLY on the ground station.
RECEIVER_KEM_PRIVATE_KEY_PATH = "dev_secrets/groundstation/receiver_kem_private.key"


# ---------------------------------------------------------------------
# Load key material
# ---------------------------------------------------------------------
# Public key used to verify packets came from the satellite.
with open(SATELLITE_MLDSA_PUBLIC_KEY_PATH, "rb") as f:
    SATELLITE_MLDSA_PUBLIC_KEY = f.read()

# Private key used to recover the shared secret from KEM ciphertext.
with open(RECEIVER_KEM_PRIVATE_KEY_PATH, "rb") as f:
    RECEIVER_KEM_PRIVATE_KEY = f.read()


# ---------------------------------------------------------------------
# Runtime objects
# ---------------------------------------------------------------------
# Open the serial port so we can receive LoRa packets.
ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)

# Key manager handles ML-KEM decapsulation and AES session-key derivation.
key_manager = KeyManager()

# Anomaly detector for accepted packets.
detector = RuntimeDetector()

# Per-session state:
# sessions[session_id] -> SessionState
sessions: dict[str, object] = {}

# replay_windows[session_id] -> ReplayWindow
replay_windows: dict[str, ReplayWindow] = {}

# Print startup banner.
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
    return datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


# ---------------------------------------------------------------------
# Main receive loop
# ---------------------------------------------------------------------
while True:
    # Read one line from the serial port.
    raw_line = ser.readline()

    # If nothing was received, loop again.
    if not raw_line:
        continue

    try:
        # -------------------------------------------------------------
        # Step 1: Parse the outer packet wrapper
        # -------------------------------------------------------------
        # The transmitter sends newline-delimited JSON.
        packet = json.loads(raw_line.decode("utf-8"))

        # -------------------------------------------------------------
        # Step 2: Rebuild the exact signed packet core
        # -------------------------------------------------------------
        # The transmitter signs these fields, so we must reconstruct them
        # exactly before verifying the ML-DSA signature.
        packet_core = {
            "spacecraft_id": packet["spacecraft_id"],
            "session_id": packet["session_id"],
            "algorithms": packet["algorithms"],
            "kem_ciphertext": packet["kem_ciphertext"],
            "nonce": packet["nonce"],
            "ciphertext": packet["ciphertext"],
        }

        # -------------------------------------------------------------
        # Step 3: Verify ML-DSA digital signature
        # -------------------------------------------------------------
        # This proves:
        # - the packet came from the expected satellite
        # - the signed packet core was not modified
        is_valid_signature = verify(
            canonical_json_bytes(packet_core),
            b64d(packet["signature"]),
            SATELLITE_MLDSA_PUBLIC_KEY,
            algorithm=MLDSA_ALGORITHM,
        )

        if not is_valid_signature:
            print("[GROUND] REJECTED: ML-DSA signature verification failed")
            continue

        # -------------------------------------------------------------
        # Step 4: Resolve or create the session for this packet
        # -------------------------------------------------------------
        # The session_id tells us which logical crypto session the packet
        # belongs to.
        session_id = packet["session_id"]

        # If we have never seen this session before, derive it now.
        if session_id not in sessions:
            print(f"[GROUND] Establishing new session: {session_id}")

            session = key_manager.create_receiver_session(
                kem_ciphertext=b64d(packet["kem_ciphertext"]),
                receiver_private_key=RECEIVER_KEM_PRIVATE_KEY,
                session_id=session_id,
            )

            sessions[session_id] = session
            replay_windows[session_id] = ReplayWindow(window_size=64)

        # Pull the already-known session and replay window.
        session = sessions[session_id]
        replay_window = replay_windows[session_id]

        # Reject expired sessions.
        if session.is_expired():
            print(f"[GROUND] REJECTED: session expired ({session_id})")
            continue

        # -------------------------------------------------------------
        # Step 5: Decrypt the ciphertext using the session AES key
        # -------------------------------------------------------------
        # This replaces the old hardcoded AES key path.
        plaintext = decrypt(
            b64d(packet["nonce"]),
            b64d(packet["ciphertext"]),
            session.aes_key,
            aad=packet["spacecraft_id"].encode("utf-8"),
        )

        # -------------------------------------------------------------
        # Step 6: Parse the decrypted telemetry frame
        # -------------------------------------------------------------
        frame = parse_json_bytes(plaintext)

        # -------------------------------------------------------------
        # Step 7: Replay protection check (per session)
        # -------------------------------------------------------------
        # Replay protection should happen only after:
        # - signature verification succeeded
        # - session was resolved
        # - decryption succeeded
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

        # -------------------------------------------------------------
        # Step 8: Compute packet gap for operator visibility
        # -------------------------------------------------------------
        gap = 0
        if previous_max != -1 and sequence > previous_max + 1:
            gap = sequence - previous_max - 1

        # -------------------------------------------------------------
        # Step 9: Run anomaly detection
        # -------------------------------------------------------------
        detection = detector.detect(frame)

        # -------------------------------------------------------------
        # Step 10: Pull out payload fields for display
        # -------------------------------------------------------------
        payload = frame["payload"]

        # -------------------------------------------------------------
        # Step 11: Print a clean operator view
        # -------------------------------------------------------------
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
        # Keep the receiver alive during testing and fuzzing.
        print(f"[GROUND] WARN: packet processing failed: {exc}")