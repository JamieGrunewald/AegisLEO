"""
[LEGACY — DO NOT USE IN PRODUCTION]

This is an earlier, pre-hardened version of the satellite transmitter retained
for historical reference only. It lacks the transport-hardened framing, selective
session_init recovery, and standardized demo logging present in transmitter.py.

Use satellite/transmitter.py for all active work.

AegisLEO Secure Satellite Telemetry Transmitter

Created by: Jamie Grunewald
Date: 2026-03-08
Version: v0.3.1

Purpose
-------
This script runs on the satellite-side node and sends secure telemetry.

What it does
------------
1. Build a CCSDS-style telemetry frame
2. Serialize the frame into deterministic JSON bytes
3. Encrypt the frame with AES-256-GCM
4. Sign the encrypted packet with ML-DSA
5. Send the final JSON envelope over the LoRa serial link

Why sign the encrypted packet instead of plaintext?
---------------------------------------------------
Because we want the receiver to verify:
- who sent it
- whether the encrypted envelope was modified

Then, after signature verification succeeds, the receiver decrypts it.

Current lab note
----------------
The AES key below is hardcoded as a demo/shared key.

This is only a staging step.

Later:
- ML-KEM (FIPS 203) should establish this key dynamically
"""

from __future__ import annotations

import json
import random
import time
import serial

from ccsds.frame import build_frame, canonical_json_bytes
from crypto.aes_gcm import encrypt
from crypto.mldsa_signatures import sign, b64e


# ---------------------------------------------------------------------
# Serial / radio settings
# ---------------------------------------------------------------------
# Change this if your LoRa serial device path differs on the satellite node.
SERIAL_PORT = "/dev/ttyACM0"
BAUD_RATE = 115200

# Logical identity of this sending node
SPACECRAFT_ID = "AegisLEO-SAT-1"

# Application Process ID
APID = 100

# ---------------------------------------------------------------------
# Demo AES key
# ---------------------------------------------------------------------
# AES-256 requires 32 bytes.
# This is a placeholder until ML-KEM is added.
AES_KEY = b"0123456789ABCDEF0123456789ABCDEF"

# ---------------------------------------------------------------------
# ML-DSA algorithm
# ---------------------------------------------------------------------
MLDSA_ALGORITHM = "ML-DSA-65"


# ---------------------------------------------------------------------
# Load the satellite private signing key
# ---------------------------------------------------------------------
# This key MUST stay on the sender side.
with open("keys/satellite_mldsa_secret.key", "rb") as f:
    MLDSA_SECRET_KEY = f.read()


# ---------------------------------------------------------------------
# Open the serial interface to the LoRa radio
# ---------------------------------------------------------------------
ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)

# Packet sequence counter
sequence = 1

print("Satellite secure transmitter online")
print(f"Serial port: {SERIAL_PORT}")
print(f"Baud rate  : {BAUD_RATE}")
print(f"Spacecraft : {SPACECRAFT_ID}")
print("Press Ctrl+C to stop.")


while True:
    # -------------------------------------------------------------
    # Step 1: Create simulated telemetry values
    # -------------------------------------------------------------
    # In a real system, these would come from sensors, subsystem status,
    # power telemetry, attitude data, etc.
    payload = {
        "temp_c": round(random.uniform(11.5, 15.5), 2),
        "bus_v": round(random.uniform(4.85, 5.15), 2),
        "bus_i": round(random.uniform(0.30, 0.65), 3),
        "state": random.choice(["NOMINAL", "SUNPOINT", "TX_WINDOW"]),
    }

    # -------------------------------------------------------------
    # Step 2: Build the CCSDS-style frame
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
    # We do this so signing and verification use exactly the same bytes.
    frame_bytes = canonical_json_bytes(frame)

    # -------------------------------------------------------------
    # Step 4: Encrypt the frame with AES-GCM
    # -------------------------------------------------------------
    # AAD = Additional Authenticated Data
    # We bind the encryption context to the spacecraft ID.
    encrypted = encrypt(
        frame_bytes,
        AES_KEY,
        aad=SPACECRAFT_ID.encode("utf-8"),
    )

    # -------------------------------------------------------------
    # Step 5: Build the packet core
    # -------------------------------------------------------------
    # This is the structured envelope that will travel over the wire.
    # We base64-encode nonce/ciphertext because JSON cannot carry raw bytes.
    packet_core = {
        "spacecraft_id": SPACECRAFT_ID,
        "algorithms": {
            "enc": "AES-256-GCM",
            "sig": MLDSA_ALGORITHM,
        },
        "nonce": b64e(encrypted["nonce"]),
        "ciphertext": b64e(encrypted["ciphertext"]),
    }

    # -------------------------------------------------------------
    # Step 6: Sign the packet core
    # -------------------------------------------------------------
    # We sign the canonical form of the encrypted envelope.
    packet_core_bytes = canonical_json_bytes(packet_core)
    signature = sign(
        packet_core_bytes,
        MLDSA_SECRET_KEY,
        algorithm=MLDSA_ALGORITHM,
    )

    # -------------------------------------------------------------
    # Step 7: Build the final transmitted packet
    # -------------------------------------------------------------
    transmitted_packet = {
        **packet_core,
        "signature": b64e(signature),
    }

    # -------------------------------------------------------------
    # Step 8: Convert to newline-delimited JSON and send over serial
    # -------------------------------------------------------------
    # The newline is important because the receiver uses readline().
    wire_bytes = (json.dumps(transmitted_packet) + "\n").encode("utf-8")

    ser.write(wire_bytes)
    ser.flush()

    print(f"[SAT] TX secure packet seq={sequence} payload={payload}")

    # Move to the next packet number
    sequence += 1

    # Wait 3 seconds before sending another packet
    time.sleep(3)