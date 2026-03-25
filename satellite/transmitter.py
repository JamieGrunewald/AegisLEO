"""
AegisLEO Secure Satellite Telemetry Transmitter (Chunked RF Version)

Created by: Jamie Grunewald
Date: 2026-03-24
Version: v0.7.0

Purpose
-------
This script runs on the satellite-side node and sends secure telemetry
to the ground station over the LoRa serial link.

What this transmitter does
--------------------------
For every telemetry update, it will:

1. Load the ground station's ML-KEM public key
2. Create a PQ session and derive an AES-256 session key
3. Build a signed session_init packet
4. Chunk that packet into small RF-safe transport chunks
5. Send session_init chunks once
6. Build encrypted + signed telemetry packets
7. Chunk telemetry packets into small RF-safe transport chunks
8. Send those chunks over serial/LoRa

Why chunking exists
-------------------
LoRa transparent serial bridges are not great at carrying large JSON blobs.
So instead of sending one giant packet, we:

- serialize the full logical packet
- base64-encode it
- split it into small chunks
- send one chunk per line of JSON

The receiver reassembles the pieces.

Security note
-------------
This version keeps:
- ML-KEM for session establishment
- AES-GCM for telemetry confidentiality + integrity
- ML-DSA signatures on the full logical packets

So we are not throwing security away.
We are only changing the transport format.
"""

from __future__ import annotations

import base64
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

# Small chunk size for RF safety.
# You can tune this later if needed.
CHUNK_SIZE = 80

# Small pause between chunk transmissions so we do not overwhelm the radio.
CHUNK_DELAY_SECONDS = 0.05


# ---------------------------------------------------------------------
# Crypto / key file settings
# ---------------------------------------------------------------------
MLDSA_ALGORITHM = "ML-DSA-65"

SATELLITE_MLDSA_SECRET_KEY_PATH = "keys/satellite_mldsa_secret.key"
RECEIVER_KEM_PUBLIC_KEY_PATH = "dev_secrets/satellite/receiver_kem_public.key"


# ---------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------
def packet_to_base64(packet: dict) -> str:
    """
    Convert a full logical packet into compact JSON bytes, then base64 text.

    Why we do this
    --------------
    The full packet may contain lots of characters that are awkward to split
    directly inside another JSON wrapper.

    Base64 gives us a safe ASCII payload made of simple characters.
    """
    raw = json.dumps(packet, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("utf-8")


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
) -> list[dict]:
    """
    Wrap a long base64 payload in small transport chunks.

    Chunk packet format
    -------------------
    t   -> transport type
    sid -> session ID
    mid -> message ID (telemetry only)
    i   -> chunk index
    n   -> total number of chunks
    d   -> data fragment
    """
    fragments = split_chunks(encoded_payload, chunk_size)
    total = len(fragments)

    packets: list[dict] = []
    for idx, frag in enumerate(fragments):
        pkt = {
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


def send_chunk_packets(ser: serial.Serial, packets: list[dict]) -> None:
    """
    Send chunk packets one line at a time.

    Each chunk packet is small and newline-delimited so the receiver can
    consume one transport chunk at a time.
    """
    for pkt in packets:
        wire_bytes = (json.dumps(pkt, separators=(",", ":")) + "\n").encode("utf-8")
        ser.write(wire_bytes)
        ser.flush()
        time.sleep(CHUNK_DELAY_SECONDS)


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
# Send session_init once
# ---------------------------------------------------------------------
# Step 1: Build the unsigned session_init core
session_init_core = {
    "type": "session_init",
    "spacecraft_id": SPACECRAFT_ID,
    "session_id": session.session_id,
    "kem_ciphertext": b64e(kem_ciphertext),
}

# Step 2: Sign the session_init core
session_init_signature = sign(
    canonical_json_bytes(session_init_core),
    MLDSA_SECRET_KEY,
    algorithm=MLDSA_ALGORITHM,
)

# Step 3: Build the final logical session_init packet
session_init_packet = {
    **session_init_core,
    "signature": b64e(session_init_signature),
}

# Step 4: Convert the full logical packet to base64 text
session_init_b64 = packet_to_base64(session_init_packet)

# Step 5: Split into small RF-safe transport chunks
session_init_chunks = make_chunk_packets(
    chunk_type="si",              # session_init transport chunk
    session_id=session.session_id,
    encoded_payload=session_init_b64,
    chunk_size=CHUNK_SIZE,
)

# Step 6: Send all chunks
send_chunk_packets(ser, session_init_chunks)

print(
    f"[SAT] Sent session_init for session={session.session_id} "
    f"({len(session_init_chunks)} chunks)"
)

# Small pause so the receiver has time to establish the session.
time.sleep(1)


# ---------------------------------------------------------------------
# Main telemetry loop
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
    # Step 3: Convert frame into deterministic bytes
    # -------------------------------------------------------------
    frame_bytes = canonical_json_bytes(frame)

    # -------------------------------------------------------------
    # Step 4: Encrypt the telemetry frame with AES-GCM
    # -------------------------------------------------------------
    encrypted = encrypt(
        frame_bytes,
        session.aes_key,
        aad=SPACECRAFT_ID.encode("utf-8"),
    )

    # -------------------------------------------------------------
    # Step 5: Build the unsigned telemetry packet core
    # -------------------------------------------------------------
    packet_core = {
        "type": "telemetry",
        "spacecraft_id": SPACECRAFT_ID,
        "session_id": session.session_id,
        "nonce": b64e(encrypted["nonce"]),
        "ciphertext": b64e(encrypted["ciphertext"]),
    }

    # -------------------------------------------------------------
    # Step 6: Sign the telemetry packet core
    # -------------------------------------------------------------
    telemetry_signature = sign(
        canonical_json_bytes(packet_core),
        MLDSA_SECRET_KEY,
        algorithm=MLDSA_ALGORITHM,
    )

    # -------------------------------------------------------------
    # Step 7: Build the final logical telemetry packet
    # -------------------------------------------------------------
    transmitted_packet = {
        **packet_core,
        "signature": b64e(telemetry_signature),
    }

    # -------------------------------------------------------------
    # Step 8: Convert logical telemetry packet to base64 text
    # -------------------------------------------------------------
    telemetry_b64 = packet_to_base64(transmitted_packet)

    # -------------------------------------------------------------
    # Step 9: Split telemetry into RF-safe chunks
    # -------------------------------------------------------------
    telemetry_chunks = make_chunk_packets(
        chunk_type="tc",              # telemetry transport chunk
        session_id=session.session_id,
        encoded_payload=telemetry_b64,
        chunk_size=CHUNK_SIZE,
        message_id=sequence,          # helps receiver group chunk sets
    )

    # -------------------------------------------------------------
    # Step 10: Send telemetry chunks
    # -------------------------------------------------------------
    send_chunk_packets(ser, telemetry_chunks)

    print(
        f"[SAT] TX secure packet "
        f"session={session.session_id} seq={sequence} "
        f"chunks={len(telemetry_chunks)} payload={payload}"
    )

    # -------------------------------------------------------------
    # Step 11: Increment packet sequence number and wait
    # -------------------------------------------------------------
    sequence += 1
    time.sleep(3)