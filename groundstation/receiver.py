"""
AegisLEO Ground Station Secure Receiver

Created by: Jamie Grunewald
Date: 2026-03-23
Version: v0.4.0

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
4. Decrypt the ciphertext using AES-GCM
5. Parse the decrypted CCSDS-style telemetry frame
6. Check replay protection using the sequence number
7. Run lightweight anomaly detection
8. Print the packet contents in a readable format

Why this matters
----------------
This gives us a layered security pipeline:

- ML-DSA verifies the sender is trusted
- AES-GCM protects confidentiality and integrity
- ReplayWindow blocks duplicated / stale packets
- RuntimeDetector gives us a place to add ML anomaly detection

Important note
--------------
Right now this file still uses a hardcoded AES key.
Later, this should be replaced with a session key derived
from the ML-KEM handshake via key_manager.py.
"""

from __future__ import annotations

# Standard library imports
import json
from datetime import datetime, UTC

# Third-party import for serial communication with the LoRa radio
import serial

# Project imports:
# These are the helper modules we already built in the repo.
from ccsds.frame import canonical_json_bytes, parse_json_bytes
from crypto.aes_gcm import decrypt
from crypto.mldsa_signatures import verify, b64d
from groundstation.replay_window import ReplayWindow
from models.runtime_detector import RuntimeDetector


# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------
# Serial device path for the LoRa receiver attached to the ground station.
# This path may be different on your system.
SERIAL_PORT = "/dev/serial/by-id/usb-1a86_USB_Single_Serial_5AAF186928-if00"

# Baud rate for the serial link.
BAUD_RATE = 115200

# IMPORTANT:
# This is still a temporary hardcoded AES-256 key for lab testing.
# Later this should be replaced with a session key from ML-KEM.
AES_KEY = b"0123456789ABCDEF0123456789ABCDEF"

# ML-DSA signing algorithm being used for signature verification.
MLDSA_ALGORITHM = "ML-DSA-65"


# Load the satellite's ML-DSA public key.
# We use this to verify that incoming packets were signed by the expected sender.
with open("keys/satellite_mldsa_public.key", "rb") as f:
    SATELLITE_MLDSA_PUBLIC_KEY = f.read()


# ---------------------------------------------------------------------
# Runtime objects
# ---------------------------------------------------------------------
# Open the serial port so we can receive LoRa packets.
ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)

# Replay protection window.
# This tracks which recent sequence numbers we have already seen.
# If a packet is duplicated or too old, it will be rejected.
replay_window = ReplayWindow(window_size=64)

# Lightweight anomaly detector.
# Right now this is a placeholder/rule-based detector.
# Later it can be replaced with an autoencoder model.
detector = RuntimeDetector()

# Print startup banner so we know the receiver is alive.
print("Ground station secure receiver online")
print(f"Serial port: {SERIAL_PORT}")
print(f"Baud rate  : {BAUD_RATE}")
print("Press Ctrl+C to stop.")


# ---------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------
def pretty_time(epoch: int) -> str:
    """
    Convert a Unix timestamp into a human-readable UTC string.

    Example:
        1772930000 -> 2026-03-06 12:13:20 UTC
    """
    return datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


# ---------------------------------------------------------------------
# Main receive loop
# ---------------------------------------------------------------------
# This loop runs forever until you stop the script manually.
while True:
    # Read one line of input from the serial port.
    # The sender is expected to send one JSON packet per line.
    raw_line = ser.readline()

    # If nothing was read, go back and try again.
    if not raw_line:
        continue

    try:
        # -------------------------------------------------------------
        # Step 1: Parse the outer packet wrapper
        # -------------------------------------------------------------
        # The outer packet is JSON that contains things like:
        # - spacecraft_id
        # - algorithms
        # - nonce
        # - ciphertext
        # - signature
        packet = json.loads(raw_line.decode("utf-8"))

        # -------------------------------------------------------------
        # Step 2: Build the exact packet content that was signed
        # -------------------------------------------------------------
        # We only verify the core fields that were included in the
        # sender's signing operation.
        packet_core = {
            "spacecraft_id": packet["spacecraft_id"],
            "algorithms": packet["algorithms"],
            "nonce": packet["nonce"],
            "ciphertext": packet["ciphertext"],
        }

        # -------------------------------------------------------------
        # Step 3: Verify ML-DSA digital signature
        # -------------------------------------------------------------
        # This proves the packet came from the trusted sender and
        # that the signed content was not modified in transit.
        is_valid_signature = verify(
            canonical_json_bytes(packet_core),          # exact bytes that were signed
            b64d(packet["signature"]),                  # decode signature from base64
            SATELLITE_MLDSA_PUBLIC_KEY,                 # verify against satellite public key
            algorithm=MLDSA_ALGORITHM,
        )

        # If signature verification fails, reject the packet immediately.
        if not is_valid_signature:
            print("[GROUND] REJECTED: ML-DSA signature verification failed")
            continue

        # -------------------------------------------------------------
        # Step 4: Decrypt the ciphertext using AES-GCM
        # -------------------------------------------------------------
        # AES-GCM gives us confidentiality + authenticated decryption.
        # If the ciphertext or nonce is wrong/tampered with,
        # decryption should fail.
        plaintext = decrypt(
            b64d(packet["nonce"]),                      # nonce decoded from base64
            b64d(packet["ciphertext"]),                 # ciphertext decoded from base64
            AES_KEY,                                    # current lab AES key
            aad=packet["spacecraft_id"].encode("utf-8"),# additional authenticated data
        )

        # -------------------------------------------------------------
        # Step 5: Parse the decrypted telemetry frame
        # -------------------------------------------------------------
        # The decrypted data should be our CCSDS-inspired telemetry frame.
        frame = parse_json_bytes(plaintext)

        # -------------------------------------------------------------
        # Step 6: Replay protection check
        # -------------------------------------------------------------
        # We use the frame sequence number to detect:
        # - duplicate packets
        # - stale packets
        # - packets outside the allowed sliding window
        sequence = int(frame["sequence"])

        # First check whether the packet WOULD be accepted.
        # This lets us know the reason before mutating state.
        decision = replay_window.check(sequence)

        # If replay protection says no, reject the packet.
        if not decision.accepted:
            print(
                f"[GROUND] REJECTED: replay protection blocked packet "
                f"(seq={sequence}, reason={decision.reason})"
            )
            continue

        # Save the current max sequence before recording the new one.
        # This helps us calculate whether there was a sequence gap.
        previous_max = replay_window.max_seq

        # Record the accepted sequence number in the replay window.
        replay_window.record(sequence)

        # -------------------------------------------------------------
        # Step 7: Compute packet gap for operator visibility
        # -------------------------------------------------------------
        # This is NOT replay protection.
        # This is just a nice metric to show whether packets appear missing.
        gap = 0
        if previous_max != -1 and sequence > previous_max + 1:
            gap = sequence - previous_max - 1

        # -------------------------------------------------------------
        # Step 8: Run anomaly detection
        # -------------------------------------------------------------
        # Right now the runtime detector is lightweight.
        # Later this can wrap a real autoencoder running on the Orin Nano.
        detection = detector.detect(frame)

        # -------------------------------------------------------------
        # Step 9: Pull out payload fields for display
        # -------------------------------------------------------------
        payload = frame["payload"]

        # -------------------------------------------------------------
        # Step 10: Print a clean operator view of the packet
        # -------------------------------------------------------------
        print("=" * 72)
        print("AegisLEO Secure Telemetry Packet")
        print(f"Spacecraft : {frame['spacecraft_id']}")
        print(f"Timestamp  : {pretty_time(frame['timestamp'])}")
        print(f"APID       : {frame['apid']}")
        print(f"Sequence   : {sequence}")
        print(f"Gap        : {gap}")
        print(f"Replay     : ACCEPTED ({decision.reason})")

        # Show ML/anomaly result
        if detection.is_anomalous:
            print(
                f"ML         : ANOMALY "
                f"(score={detection.score}, reasons={detection.reasons})"
            )
        else:
            print(f"ML         : nominal (score={detection.score})")

        # Show crypto status summary
        print("Crypto     : signature=VALID, decrypt=SUCCESS")

        # Show the telemetry payload values
        print(
            f"Payload    : temp_c={payload['temp_c']} "
            f"bus_v={payload['bus_v']} "
            f"bus_i={payload['bus_i']} "
            f"state={payload['state']}"
        )
        print("=" * 72)

    except Exception as exc:
        # Catch any error so the receiver keeps running.
        # This is useful during development and packet fuzzing.
        print(f"[GROUND] WARN: packet processing failed: {exc}")