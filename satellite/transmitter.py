"""
AegisLEO Secure Satellite Telemetry Transmitter
Chunked RF Version with ACK/NACK Retransmission

Created by: Jamie Grunewald
Date: 2026-03-24
Version: v0.8.0

Purpose
-------
This script runs on the satellite-side node and sends secure telemetry
to the ground station over the LoRa serial link.

What this version adds
----------------------
This version adds:

- RF-safe chunking
- line-based transport packets
- ACK handling
- NACK handling
- selective chunk retransmission

Why ACK/NACK matters
--------------------
LoRa links can lose or delay packets.

So instead of blindly transmitting and hoping for the best, we:

1. send chunk packets
2. keep a copy of each sent chunk set
3. wait for ACK from the receiver
4. if NACK arrives, retransmit only missing chunks
5. if ACK arrives, clear the sent message from memory

Security model
--------------
This version preserves the logical security model:
- session_init logical packet is signed
- telemetry logical packet is signed
- telemetry payload is encrypted with AES-GCM

Chunking only changes transport format.
"""

from __future__ import annotations

import base64
import json
import random
import select
import time
from typing import Any

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

# RF-safe chunk tuning
CHUNK_SIZE = 32
CHUNK_DELAY_SECONDS = 0.15

# How long to wait for an ACK after sending a message chunk set
ACK_WAIT_SECONDS = 2.0

# How many times to retry a message after NACK / timeout
MAX_RETRIES = 3

# Debug controls
DEBUG_TX_CHUNKS = True
DEBUG_ACKS = True


# ---------------------------------------------------------------------
# Crypto / key file settings
# ---------------------------------------------------------------------
MLDSA_ALGORITHM = "ML-DSA-65"

SATELLITE_MLDSA_SECRET_KEY_PATH = "keys/satellite_mldsa_secret.key"
RECEIVER_KEM_PUBLIC_KEY_PATH = "dev_secrets/satellite/receiver_kem_public.key"


# ---------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------
def packet_to_base64(packet: dict[str, Any]) -> str:
    """
    Convert one full logical packet into compact JSON bytes, then base64 text.

    Why we do this
    --------------
    The full logical packet may be large and contain many characters.
    Base64 turns it into safe ASCII text that is easy to split into chunks.
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
) -> list[dict[str, Any]]:
    """
    Wrap a long encoded payload in small transport chunk packets.

    Transport chunk packet fields
    -----------------------------
    t   -> chunk type ("si" or "tc")
    sid -> session ID
    mid -> logical message ID (used for telemetry, omitted for session_init)
    i   -> chunk index
    n   -> total chunks
    d   -> data fragment
    """
    fragments = split_chunks(encoded_payload, chunk_size)
    total = len(fragments)

    packets: list[dict[str, Any]] = []
    for idx, frag in enumerate(fragments):
        pkt: dict[str, Any] = {
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


def write_transport_packet(ser: serial.Serial, pkt: dict[str, Any]) -> None:
    """
    Send exactly one small line-based transport packet.

    Important
    ---------
    The LoRa bridge behaved well with newline-delimited transport packets,
    so every write ends with '\\n'.
    """
    wire = (json.dumps(pkt, separators=(",", ":")) + "\n").encode("utf-8")
    ser.write(wire)
    ser.flush()


def send_chunk_packets(ser: serial.Serial, packets: list[dict[str, Any]]) -> None:
    """
    Send a whole set of chunk packets with a small delay between each one.
    """
    total = len(packets)
    for idx, pkt in enumerate(packets):
        write_transport_packet(ser, pkt)
        if DEBUG_TX_CHUNKS:
            print(
                f"[SAT][CHUNK] t={pkt['t']} sid={pkt['sid']} "
                f"mid={pkt.get('mid')} idx={idx + 1}/{total}"
            )
        time.sleep(CHUNK_DELAY_SECONDS)


def read_transport_line(ser: serial.Serial, timeout_seconds: float) -> dict[str, Any] | None:
    """
    Wait briefly for one incoming transport packet from the receiver.

    Used for:
    - ACK packets
    - NACK packets

    Returns None if nothing valid arrives before timeout.
    """
    end_time = time.time() + timeout_seconds

    while time.time() < end_time:
        ready, _, _ = select.select([ser.fileno()], [], [], 0.1)
        if not ready:
            continue

        line = ser.readline()
        if not line:
            continue

        try:
            return json.loads(line.decode("utf-8").strip())
        except json.JSONDecodeError:
            # Ignore malformed control-plane input
            continue

    return None


def wait_for_ack_or_nack(
    ser: serial.Serial,
    session_id: str,
    message_id: int | None,
    pending_chunks: list[dict[str, Any]],
) -> bool:
    """
    Wait for ACK/NACK and handle selective retransmission.

    Returns
    -------
    bool
        True if ACK received.
        False if delivery failed after retries.

    Behavior
    --------
    - session_init does not use a message ID, so it is matched with mid=None
    - telemetry uses the sequence number as message ID
    """
    for attempt in range(1, MAX_RETRIES + 1):
        control = read_transport_line(ser, ACK_WAIT_SECONDS)

        if control is None:
            if DEBUG_ACKS:
                print(
                    f"[SAT][ACK] timeout sid={session_id} mid={message_id} "
                    f"attempt={attempt}/{MAX_RETRIES}"
                )
            # Timeout: retransmit whole message set
            send_chunk_packets(ser, pending_chunks)
            continue

        if control.get("sid") != session_id:
            continue

        if control.get("mid") != message_id:
            continue

        control_type = control.get("t")

        if control_type == "ack":
            if DEBUG_ACKS:
                print(f"[SAT][ACK] received sid={session_id} mid={message_id}")
            return True

        if control_type == "nack":
            missing = control.get("missing", [])
            if DEBUG_ACKS:
                print(
                    f"[SAT][NACK] sid={session_id} mid={message_id} "
                    f"missing={missing} attempt={attempt}/{MAX_RETRIES}"
                )

            resend = [pkt for pkt in pending_chunks if pkt["i"] in missing]
            if not resend:
                # If missing list is weird/empty, fall back to full resend
                resend = pending_chunks
            send_chunk_packets(ser, resend)
            continue

    return False


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
# Open serial interface to the LoRa radio
# ---------------------------------------------------------------------
ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)

# Logical telemetry sequence counter
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
# Step 1: Build unsigned session_init core
session_init_core = {
    "type": "session_init",
    "spacecraft_id": SPACECRAFT_ID,
    "session_id": session.session_id,
    "kem_ciphertext": b64e(kem_ciphertext),
}

# Step 2: Sign session_init logical packet
session_init_signature = sign(
    canonical_json_bytes(session_init_core),
    MLDSA_SECRET_KEY,
    algorithm=MLDSA_ALGORITHM,
)

# Step 3: Build final logical session_init packet
session_init_packet = {
    **session_init_core,
    "signature": b64e(session_init_signature),
}

# Step 4: Convert to base64 text for chunking
session_init_b64 = packet_to_base64(session_init_packet)

# Step 5: Build RF transport chunks
session_init_chunks = make_chunk_packets(
    chunk_type="si",
    session_id=session.session_id,
    encoded_payload=session_init_b64,
    chunk_size=CHUNK_SIZE,
    message_id=None,
)

# Step 6: Send all chunks
send_chunk_packets(ser, session_init_chunks)

print(
    f"[SAT] Sent session_init for session={session.session_id} "
    f"({len(session_init_chunks)} chunks)"
)

# Step 7: Wait for ACK/NACK from receiver
session_init_ok = wait_for_ack_or_nack(
    ser=ser,
    session_id=session.session_id,
    message_id=None,
    pending_chunks=session_init_chunks,
)

if not session_init_ok:
    print("[SAT] ERROR: session_init delivery failed after retries")
    raise SystemExit(1)

print("[SAT] session_init acknowledged by ground station")

# Small pause so ground station can finish session setup
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
    # Step 2: Build CCSDS-inspired telemetry frame
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
    # Step 4: Encrypt telemetry frame with AES-GCM
    # -------------------------------------------------------------
    encrypted = encrypt(
        frame_bytes,
        session.aes_key,
        aad=SPACECRAFT_ID.encode("utf-8"),
    )

    # -------------------------------------------------------------
    # Step 5: Build unsigned telemetry logical packet
    # -------------------------------------------------------------
    packet_core = {
        "type": "telemetry",
        "spacecraft_id": SPACECRAFT_ID,
        "session_id": session.session_id,
        "nonce": b64e(encrypted["nonce"]),
        "ciphertext": b64e(encrypted["ciphertext"]),
    }

    # -------------------------------------------------------------
    # Step 6: Sign logical telemetry packet
    # -------------------------------------------------------------
    telemetry_signature = sign(
        canonical_json_bytes(packet_core),
        MLDSA_SECRET_KEY,
        algorithm=MLDSA_ALGORITHM,
    )

    # -------------------------------------------------------------
    # Step 7: Build final logical telemetry packet
    # -------------------------------------------------------------
    transmitted_packet = {
        **packet_core,
        "signature": b64e(telemetry_signature),
    }

    # -------------------------------------------------------------
    # Step 8: Convert full logical telemetry packet to base64 text
    # -------------------------------------------------------------
    telemetry_b64 = packet_to_base64(transmitted_packet)

    # -------------------------------------------------------------
    # Step 9: Split logical telemetry packet into RF-safe chunks
    # -------------------------------------------------------------
    telemetry_chunks = make_chunk_packets(
        chunk_type="tc",
        session_id=session.session_id,
        encoded_payload=telemetry_b64,
        chunk_size=CHUNK_SIZE,
        message_id=sequence,
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
    # Step 11: Wait for ACK/NACK
    # -------------------------------------------------------------
    delivery_ok = wait_for_ack_or_nack(
        ser=ser,
        session_id=session.session_id,
        message_id=sequence,
        pending_chunks=telemetry_chunks,
    )

    if not delivery_ok:
        print(f"[SAT] ERROR: telemetry seq={sequence} failed after retries")

    # -------------------------------------------------------------
    # Step 12: Move to next telemetry message
    # -------------------------------------------------------------
    sequence += 1
    time.sleep(3)