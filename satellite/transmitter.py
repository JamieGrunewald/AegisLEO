"""
AegisLEO Secure Satellite Telemetry Transmitter

Created by: Jamie Grunewald
Date: 2026-03-24
Version: v0.5.0

Purpose
-------
This script runs on the satellite-side node and sends secure telemetry
to the ground station over the LoRa serial link.

What this transmitter does
--------------------------
For every packet it sends, it will:

1. Load the ground station's ML-KEM public key
2. Create a PQ session and derive an AES-256 session key
3. Create simulated telemetry values
4. Build a CCSDS-inspired telemetry frame
5. Convert that frame into deterministic JSON bytes
6. Encrypt the frame using the session AES key
7. Build an outer packet envelope with KEM metadata
8. Sign the encrypted envelope using ML-DSA
9. Send the final JSON packet over serial

Why this matters
----------------
This gives the transmitter a layered security flow:

- CCSDS-style frame gives structure to telemetry
- ML-KEM establishes a shared session key dynamically
- AES-GCM protects confidentiality and integrity
- ML-DSA proves the packet came from the expected sender

Important note
--------------
This version replaces the old hardcoded AES key with a session key
derived from ML-KEM via key_manager.py.
"""

from __future__ import annotations

import json
import random
import time

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


# ---------------------------------------------------------------------
# Crypto / key file settings
# ---------------------------------------------------------------------
MLDSA_ALGORITHM = "ML-DSA-65"

# Satellite private signing key
SATELLITE_MLDSA_SECRET_KEY_PATH = "keys/satellite_mldsa_secret.key"

# Ground station public KEM key
RECEIVER_KEM_PUBLIC_KEY_PATH = "dev_secrets/satellite/receiver_kem_public.key"


# ---------------------------------------------------------------------
# Load the satellite private signing key
# ---------------------------------------------------------------------
with open(SATELLITE_MLDSA_SECRET_KEY_PATH, "rb") as f:
    MLDSA_SECRET_KEY = f.read()


# ---------------------------------------------------------------------
# Load the ground station KEM public key
# ---------------------------------------------------------------------
# This public key is safe to place on the satellite side.
# It lets the satellite encapsulate a shared secret that only the
# ground station can decapsulate with its private key.
with open(RECEIVER_KEM_PUBLIC_KEY_PATH, "rb") as f:
    RECEIVER_KEM_PUBLIC_KEY = f.read()


# ---------------------------------------------------------------------
# Create PQ session at startup
# ---------------------------------------------------------------------
# The transmitter acts as the initiator:
# - it uses the receiver public key
# - it gets back a session object and a KEM ciphertext
# - the session contains the AES key we will use for encryption
key_manager = KeyManager()

initiator_handshake = key_manager.create_initiator_session(
    RECEIVER_KEM_PUBLIC_KEY
)

session = initiator_handshake.session
kem_ciphertext = initiator_handshake.kem_ciphertext


# ---------------------------------------------------------------------
# Open the serial interface to the LoRa radio
# ---------------------------------------------------------------------
ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)

# Packet sequence counter
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
# Main transmit loop
# ---------------------------------------------------------------------
while True:
    # -------------------------------------------------------------
    # Step 1: Create simulated telemetry values
    # -------------------------------------------------------------
    payload = {
        "temp_c": round(random.uniform(11.5, 15.5), 2),
        "bus_v": round(random.uniform(4.85, 5.15), 2),
        "bus_i": round(random.uniform(0.30, 0.65), 3),
        "state": random.choice(["NOMINAL", "SUNPOINT", "TX_WINDOW"]),
    }

    # -------------------------------------------------------------
    # Step 2: Build the CCSDS-inspired telemetry frame
    # -------------------------------------------------------------
    frame = build_frame(
        spacecraft_id=SPACECRAFT_ID,
        sequence=sequence,
        apid=APID,
        payload=payload,
    )

    # -------------------------------------------------------------
    # Step 3: Convert the frame into deterministic JSON bytes
    # -------------------------------------------------------------
    frame_bytes = canonical_json_bytes(frame)

    # -------------------------------------------------------------
    # Step 4: Encrypt the telemetry frame with the session AES key
    # -------------------------------------------------------------
    encrypted = encrypt(
        frame_bytes,
        session.aes_key,
        aad=SPACECRAFT_ID.encode("utf-8"),
    )

    # -------------------------------------------------------------
    # Step 5: Build the packet core
    # -------------------------------------------------------------
    # This is the signed envelope that travels over the wire.
    # It now includes:
    # - session_id
    # - KEM algorithm
    # - KEM ciphertext
    #
    # For this bring-up phase, we include kem_ciphertext on every packet
    # to keep the receiver logic simple and robust.
    packet_core = {
        "spacecraft_id": SPACECRAFT_ID,
        "session_id": session.session_id,
        "algorithms": {
            "enc": "AES-256-GCM",
            "sig": MLDSA_ALGORITHM,
            "kem": key_manager.algorithm,
        },
        "kem_ciphertext": b64e(kem_ciphertext),
        "nonce": b64e(encrypted["nonce"]),
        "ciphertext": b64e(encrypted["ciphertext"]),
    }

    # -------------------------------------------------------------
    # Step 6: Sign the encrypted packet core with ML-DSA
    # -------------------------------------------------------------
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
    # Step 8: Convert packet to newline-delimited JSON
    # -------------------------------------------------------------
    wire_bytes = (json.dumps(transmitted_packet) + "\n").encode("utf-8")

    # -------------------------------------------------------------
    # Step 9: Send the packet over the serial link
    # -------------------------------------------------------------
    ser.write(wire_bytes)
    ser.flush()

    print(
        f"[SAT] TX secure packet "
        f"session={session.session_id} seq={sequence} payload={payload}"
    )

    # -------------------------------------------------------------
    # Step 10: Increment sequence number
    # -------------------------------------------------------------
    sequence += 1

    # -------------------------------------------------------------
    # Step 11: Wait before sending the next packet
    # -------------------------------------------------------------
    time.sleep(3)