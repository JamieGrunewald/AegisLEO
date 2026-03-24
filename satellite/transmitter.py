"""
AegisLEO Secure Satellite Telemetry Transmitter

Created by: Jamie Grunewald
Date: 2026-03-23
Version: v0.4.0

Purpose
-------
This script runs on the satellite-side node and sends secure telemetry
to the ground station over the LoRa serial link.

What this transmitter does
--------------------------
For every packet it sends, it will:

1. Create simulated telemetry values
2. Build a CCSDS-inspired telemetry frame
3. Convert that frame into deterministic JSON bytes
4. Encrypt the frame using AES-256-GCM
5. Build an outer packet envelope
6. Sign the encrypted envelope using ML-DSA
7. Send the final JSON packet over serial

Why this matters
----------------
This gives the transmitter a layered security flow:

- CCSDS-style frame gives structure to telemetry
- AES-GCM protects confidentiality and integrity
- ML-DSA proves the packet came from the expected sender

Important note
--------------
Right now this file still uses a hardcoded AES key.
Later, this should be replaced with a session key derived
from ML-KEM via key_manager.py.
"""

from __future__ import annotations

# Standard library imports
import json
import random
import time

# Third-party import for serial communication
import serial

# Project helper modules
from ccsds.frame import build_frame, canonical_json_bytes
from crypto.aes_gcm import encrypt
from crypto.mldsa_signatures import sign, b64e


# ---------------------------------------------------------------------
# Serial / radio settings
# ---------------------------------------------------------------------
# Path to the LoRa radio serial device on the satellite node.
# Change this if your hardware enumerates differently.
SERIAL_PORT = "/dev/ttyACM0"

# Serial baud rate for talking to the LoRa device.
BAUD_RATE = 115200

# Logical identity of this sending node.
# This value is used in both the telemetry frame and the outer packet.
SPACECRAFT_ID = "AegisLEO-SAT-1"

# Application Process ID.
# This helps label what class of telemetry is being sent.
APID = 100


# ---------------------------------------------------------------------
# Demo AES key
# ---------------------------------------------------------------------
# AES-256 requires a 32-byte key.
# This is still a temporary shared demo key for the lab.
# Later, this should be replaced by a per-session key established with ML-KEM.
AES_KEY = b"0123456789ABCDEF0123456789ABCDEF"


# ---------------------------------------------------------------------
# ML-DSA settings
# ---------------------------------------------------------------------
# ML-DSA algorithm used to sign the packet envelope.
MLDSA_ALGORITHM = "ML-DSA-65"


# ---------------------------------------------------------------------
# Load the satellite private signing key
# ---------------------------------------------------------------------
# This is the satellite's private ML-DSA key.
# It MUST remain on the sender side only.
# The ground station uses the corresponding public key to verify signatures.
with open("keys/satellite_mldsa_secret.key", "rb") as f:
    MLDSA_SECRET_KEY = f.read()


# ---------------------------------------------------------------------
# Open the serial interface to the LoRa radio
# ---------------------------------------------------------------------
# We open the serial port once at startup so we can keep sending packets.
ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)

# Packet sequence counter.
# This increases every time we send a packet.
# The receiver uses it for ordering, loss awareness, and replay protection.
sequence = 1


# ---------------------------------------------------------------------
# Startup banner
# ---------------------------------------------------------------------
print("Satellite secure transmitter online")
print(f"Serial port: {SERIAL_PORT}")
print(f"Baud rate  : {BAUD_RATE}")
print(f"Spacecraft : {SPACECRAFT_ID}")
print("Press Ctrl+C to stop.")


# ---------------------------------------------------------------------
# Main transmit loop
# ---------------------------------------------------------------------
# This loop runs forever until the script is stopped manually.
while True:
    # -------------------------------------------------------------
    # Step 1: Create simulated telemetry values
    # -------------------------------------------------------------
    # In a real spacecraft or embedded node, these values would come from:
    # - thermal sensors
    # - power telemetry
    # - subsystem status
    # - attitude / control state
    #
    # For now, we generate realistic-looking values for lab testing.
    payload = {
        "temp_c": round(random.uniform(11.5, 15.5), 2),
        "bus_v": round(random.uniform(4.85, 5.15), 2),
        "bus_i": round(random.uniform(0.30, 0.65), 3),
        "state": random.choice(["NOMINAL", "SUNPOINT", "TX_WINDOW"]),
    }

    # -------------------------------------------------------------
    # Step 2: Build the CCSDS-inspired telemetry frame
    # -------------------------------------------------------------
    # This creates a structured packet that includes:
    # - protocol version
    # - spacecraft ID
    # - sequence number
    # - timestamp
    # - APID
    # - payload
    frame = build_frame(
        spacecraft_id=SPACECRAFT_ID,
        sequence=sequence,
        apid=APID,
        payload=payload,
    )

    # -------------------------------------------------------------
    # Step 3: Convert the frame into deterministic JSON bytes
    # -------------------------------------------------------------
    # We do this so that:
    # - encryption always uses a consistent byte representation
    # - later verification / debugging is easier
    #
    # Deterministic JSON means:
    # - keys are sorted
    # - whitespace is minimized
    # - same content always produces the same bytes
    frame_bytes = canonical_json_bytes(frame)

    # -------------------------------------------------------------
    # Step 4: Encrypt the telemetry frame with AES-GCM
    # -------------------------------------------------------------
    # AES-GCM gives us:
    # - confidentiality (hides telemetry contents)
    # - integrity/authenticated decryption
    #
    # AAD = Additional Authenticated Data
    # Here we bind the crypto context to the spacecraft identity.
    encrypted = encrypt(
        frame_bytes,
        AES_KEY,
        aad=SPACECRAFT_ID.encode("utf-8"),
    )

    # -------------------------------------------------------------
    # Step 5: Build the packet core
    # -------------------------------------------------------------
    # This is the outer packet envelope that will go over the wire.
    #
    # We base64-encode nonce and ciphertext because JSON cannot store raw bytes.
    # The receiver will base64-decode them before verifying and decrypting.
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
    # Step 6: Sign the encrypted packet core with ML-DSA
    # -------------------------------------------------------------
    # Important design choice:
    # We sign the encrypted envelope, not the plaintext telemetry.
    #
    # That means the receiver can verify:
    # - who sent the packet
    # - whether the envelope was modified
    #
    # Only AFTER signature verification succeeds does the receiver decrypt.
    packet_core_bytes = canonical_json_bytes(packet_core)

    signature = sign(
        packet_core_bytes,
        MLDSA_SECRET_KEY,
        algorithm=MLDSA_ALGORITHM,
    )

    # -------------------------------------------------------------
    # Step 7: Build the final transmitted packet
    # -------------------------------------------------------------
    # This is what gets sent over the wire.
    # It includes the packet core plus the digital signature.
    transmitted_packet = {
        **packet_core,
        "signature": b64e(signature),
    }

    # -------------------------------------------------------------
    # Step 8: Convert packet to newline-delimited JSON
    # -------------------------------------------------------------
    # The receiver uses readline(), so every transmitted packet must end
    # with a newline character.
    wire_bytes = (json.dumps(transmitted_packet) + "\n").encode("utf-8")

    # -------------------------------------------------------------
    # Step 9: Send the packet over the serial link
    # -------------------------------------------------------------
    ser.write(wire_bytes)
    ser.flush()

    # Print a local status message so we can see what was sent.
    print(f"[SAT] TX secure packet seq={sequence} payload={payload}")

    # -------------------------------------------------------------
    # Step 10: Increment sequence number
    # -------------------------------------------------------------
    # This helps the receiver detect:
    # - duplicates
    # - replay attempts
    # - sequence gaps
    sequence += 1

    # -------------------------------------------------------------
    # Step 11: Wait before sending the next packet
    # -------------------------------------------------------------
    # This keeps the demo readable and avoids flooding the serial link.
    time.sleep(3)