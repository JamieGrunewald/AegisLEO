"""
[LEGACY — DO NOT USE IN PRODUCTION]

This is an earlier, pre-hardened version of the ground station receiver retained
for historical reference only. It lacks the transport-hardened framing, selective
session_init recovery, replay protection, and standardized demo logging present
in receiver.py.

Use groundstation/receiver.py for all active work.

AegisLEO Secure Ground Station Receiver

Created by: Jamie Grunewald
Date: 2026-03-08
Version: v0.3.1

Purpose
-------
This script runs on the ground station and receives secure telemetry.

What it does
------------
1. Read newline-delimited JSON packets from the LoRa serial link
2. Rebuild the signed packet core
3. Verify the ML-DSA signature
4. If signature is valid, decrypt the AES-GCM ciphertext
5. Parse the original CCSDS-style frame
6. Display telemetry and packet health

Security logic
--------------
If signature verification fails:
    reject the packet

If AES-GCM decryption/authentication fails:
    reject the packet

Only after both steps succeed do we trust the payload enough to parse it.
"""

from __future__ import annotations

import json
import serial
from datetime import datetime, UTC

from ccsds.frame import canonical_json_bytes, parse_json_bytes
from crypto.aes_gcm import decrypt
from crypto.mldsa_signatures import verify, b64d


# ---------------------------------------------------------------------
# Serial / radio settings
# ---------------------------------------------------------------------
# Change this if your stable device path differs on the ground station.
SERIAL_PORT = "/dev/serial/by-id/usb-1a86_USB_Single_Serial_5AAF186928-if00"
BAUD_RATE = 115200

# ---------------------------------------------------------------------
# Demo AES key
# ---------------------------------------------------------------------
# Must match the transmitter's key exactly.
AES_KEY = b"0123456789ABCDEF0123456789ABCDEF"

# ---------------------------------------------------------------------
# ML-DSA algorithm
# ---------------------------------------------------------------------
MLDSA_ALGORITHM = "ML-DSA-65"


# ---------------------------------------------------------------------
# Load the satellite public verification key
# ---------------------------------------------------------------------
# The ground station uses the public key to verify signatures.
with open("keys/satellite_mldsa_public.key", "rb") as f:
    SATELLITE_MLDSA_PUBLIC_KEY = f.read()


# ---------------------------------------------------------------------
# Open serial interface
# ---------------------------------------------------------------------
ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)

# Keep track of packet ordering
last_sequence = None

print("Ground station secure receiver online")
print(f"Serial port: {SERIAL_PORT}")
print(f"Baud rate  : {BAUD_RATE}")
print("Press Ctrl+C to stop.")


def pretty_time(epoch: int) -> str:
    """
    Convert a Unix epoch timestamp into a human-readable UTC string.
    """
    return datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


while True:
    # -------------------------------------------------------------
    # Step 1: Read one line from the serial link
    # -------------------------------------------------------------
    raw_line = ser.readline()

    # If nothing arrived, loop again
    if not raw_line:
        continue

    try:
        # ---------------------------------------------------------
        # Step 2: Parse the transmitted JSON envelope
        # ---------------------------------------------------------
        packet = json.loads(raw_line.decode("utf-8"))

        # ---------------------------------------------------------
        # Step 3: Rebuild the exact packet_core that was signed
        # ---------------------------------------------------------
        # This must match the sender's signed structure exactly.
        packet_core = {
            "spacecraft_id": packet["spacecraft_id"],
            "algorithms": packet["algorithms"],
            "nonce": packet["nonce"],
            "ciphertext": packet["ciphertext"],
        }

        # ---------------------------------------------------------
        # Step 4: Verify ML-DSA signature
        # ---------------------------------------------------------
        is_valid = verify(
            canonical_json_bytes(packet_core),
            b64d(packet["signature"]),
            SATELLITE_MLDSA_PUBLIC_KEY,
            algorithm=MLDSA_ALGORITHM,
        )

        if not is_valid:
            print("[GROUND] REJECTED: ML-DSA signature verification failed")
            continue

        # ---------------------------------------------------------
        # Step 5: Decrypt AES-GCM ciphertext
        # ---------------------------------------------------------
        # Must use the same AAD as the transmitter.
        plaintext = decrypt(
            b64d(packet["nonce"]),
            b64d(packet["ciphertext"]),
            AES_KEY,
            aad=packet["spacecraft_id"].encode("utf-8"),
        )

        # ---------------------------------------------------------
        # Step 6: Parse the original frame
        # ---------------------------------------------------------
        frame = parse_json_bytes(plaintext)

        # ---------------------------------------------------------
        # Step 7: Sequence / packet-loss tracking
        # ---------------------------------------------------------
        sequence = int(frame["sequence"])
        gap = 0

        if last_sequence is not None and sequence > last_sequence + 1:
            gap = sequence - last_sequence - 1

        last_sequence = sequence

        # ---------------------------------------------------------
        # Step 8: Pull out payload fields for easier display
        # ---------------------------------------------------------
        payload = frame["payload"]

        # ---------------------------------------------------------
        # Step 9: Display a clean operator view
        # ---------------------------------------------------------
        print("=" * 72)
        print("AegisLEO Secure Telemetry Packet")
        print(f"Spacecraft : {frame['spacecraft_id']}")
        print(f"Timestamp  : {pretty_time(frame['timestamp'])}")
        print(f"APID       : {frame['apid']}")
        print(f"Sequence   : {sequence}")
        print(f"Gap        : {gap}")
        print("Crypto     : signature=VALID, decrypt=SUCCESS")
        print(
            f"Payload    : temp_c={payload['temp_c']} "
            f"bus_v={payload['bus_v']} "
            f"bus_i={payload['bus_i']} "
            f"state={payload['state']}"
        )
        print("=" * 72)

    except Exception as exc:
        # Any issue in parsing, verification, decryption, or field handling
        # will land here and be reported.
        print(f"[GROUND] WARN: packet processing failed: {exc}")