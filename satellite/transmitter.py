"""
AegisLEO Secure Satellite Telemetry Transmitter
Chunked RF Version with ACK/NACK Retransmission + Compression

Created by: Jamie Grunewald
Date: 2026-03-24
Version: v0.10.0

Purpose
-------
This script runs on the satellite-side node and sends secure telemetry
to the ground station over the LoRa serial link.

What this version does
----------------------
1. Builds signed logical packets
2. Encrypts telemetry with AES-GCM
3. Compresses logical packets with zlib
4. Encodes compressed bytes as base64 text
5. Splits that text into RF-safe chunks
6. Frames every transport packet with start/end markers
7. Waits for ACK/NACK from the ground station
8. Retransmits as needed

Why compression matters
-----------------------
JSON packets are text-heavy and repetitive.
Compression shrinks the logical packet before chunking.

That usually means:
- fewer RF chunks
- fewer retransmissions
- better chance of full delivery over LoRa

Why framing matters
-------------------
The LoRa serial bridge may:
- split packets
- merge packets
- inject stray bytes

So we do NOT trust newline boundaries anymore.

Instead, every transport packet is wrapped like:

    FRAME_START + JSON_BYTES + FRAME_END

The transmitter also parses ACK/NACK using the same framing.
"""

from __future__ import annotations

import base64
import json
import random
import select
import time
import zlib
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

# ACK/NACK timing
ACK_WAIT_SECONDS = 2.0
MAX_RETRIES = 3

# Transport frame markers
FRAME_START = b"\x7E"   # ~
FRAME_END = b"\x7F"

# Debug controls
DEBUG_TX_CHUNKS = False
DEBUG_ACKS = True
DEBUG_BAD_FRAMES = True
DEBUG_PACKET_SIZES = True


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
    Convert one full logical packet into compact JSON bytes,
    compress it with zlib, then encode as base64 text.

    Flow
    ----
    packet dict
        -> compact JSON bytes
        -> zlib-compressed bytes
        -> base64 text

    Why this helps
    --------------
    LoRa links are much happier when we send fewer bytes.
    Compression reduces the size before chunking.
    """
    raw = json.dumps(packet, separators=(",", ":")).encode("utf-8")
    compressed = zlib.compress(raw, level=9)
    return base64.b64encode(compressed).decode("utf-8")


def packet_to_base64_with_stats(packet: dict[str, Any]) -> tuple[str, int, int]:
    """
    Same as packet_to_base64(), but also return:
    - original JSON byte length
    - compressed byte length

    This is useful for debugging how much compression helps.
    """
    raw = json.dumps(packet, separators=(",", ":")).encode("utf-8")
    compressed = zlib.compress(raw, level=9)
    encoded = base64.b64encode(compressed).decode("utf-8")
    return encoded, len(raw), len(compressed)


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
    t   -> chunk type ("si" for session_init, "tc" for telemetry)
    sid -> session ID
    mid -> logical message ID (used for telemetry, omitted for session_init)
    i   -> chunk index
    n   -> total chunk count
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
    Send exactly one framed transport packet.

    Framing format
    --------------
    FRAME_START + JSON_BYTES + FRAME_END

    Why we do this
    --------------
    This gives the receiver hard packet boundaries even if the LoRa serial
    stream gets noisy or packets are merged together.
    """
    payload = json.dumps(pkt, separators=(",", ":")).encode("utf-8")
    wire = FRAME_START + payload + FRAME_END
    ser.write(wire)
    ser.flush()


def send_chunk_packets(ser: serial.Serial, packets: list[dict[str, Any]]) -> None:
    """
    Send a whole set of transport chunks with a small delay between each one.

    Why the delay exists
    --------------------
    LoRa modules do better when we do not flood them back-to-back.
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


def extract_framed_packets(buffer: bytearray) -> list[bytes]:
    """
    Pull as many complete framed packets as possible out of a byte buffer.

    This is used for incoming ACK/NACK control packets.
    """
    frames: list[bytes] = []

    while True:
        start = buffer.find(FRAME_START)
        if start == -1:
            # No valid frame start at all. Drop garbage and stop.
            buffer.clear()
            break

        # Drop garbage before the next frame start.
        if start > 0:
            del buffer[:start]

        end = buffer.find(FRAME_END, 1)
        if end == -1:
            # Frame not complete yet. Wait for more bytes.
            break

        frame = bytes(buffer[1:end])
        del buffer[:end + 1]
        frames.append(frame)

    return frames


def read_control_packet(ser: serial.Serial, timeout_seconds: float) -> dict[str, Any] | None:
    """
    Wait briefly for one framed ACK/NACK control packet.

    Returns
    -------
    dict | None
        Parsed ACK/NACK packet, or None if nothing valid arrives in time.
    """
    end_time = time.time() + timeout_seconds
    rx_buffer = bytearray()

    while time.time() < end_time:
        ready, _, _ = select.select([ser.fileno()], [], [], 0.1)
        if not ready:
            continue

        raw = ser.read(256)
        if not raw:
            continue

        rx_buffer.extend(raw)
        frames = extract_framed_packets(rx_buffer)

        for frame_bytes in frames:
            try:
                text = frame_bytes.decode("utf-8", errors="ignore").strip()
                if not text:
                    continue
                pkt = json.loads(text)
            except json.JSONDecodeError:
                if DEBUG_BAD_FRAMES:
                    print(f"[SAT] WARN: invalid control frame: {frame_bytes[:80]!r}")
                continue

            if pkt.get("t") in {"ack", "nack"}:
                return pkt

    return None


def wait_for_ack_or_nack(
    ser: serial.Serial,
    session_id: str,
    message_id: int | None,
    pending_chunks: list[dict[str, Any]],
) -> bool:
    """
    Wait for ACK/NACK and handle retransmission.

    Policy
    ------
    - session_init (message_id is None):
      resend the whole message on timeout/NACK
    - telemetry:
      selectively resend missing chunk indexes when NACK arrives
    """
    for attempt in range(1, MAX_RETRIES + 1):
        control = read_control_packet(ser, ACK_WAIT_SECONDS)

        if control is None:
            if DEBUG_ACKS:
                print(
                    f"[SAT][ACK] timeout sid={session_id} mid={message_id} "
                    f"attempt={attempt}/{MAX_RETRIES}"
                )
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
            # session_init: resend whole thing
            if message_id is None:
                if DEBUG_ACKS:
                    print(
                        f"[SAT][NACK] session_init sid={session_id} "
                        f"attempt={attempt}/{MAX_RETRIES} -> resend all chunks"
                    )
                send_chunk_packets(ser, pending_chunks)
                continue

            # telemetry: resend only missing indexes
            missing = control.get("m", [])
            if DEBUG_ACKS:
                print(
                    f"[SAT][NACK] sid={session_id} mid={message_id} "
                    f"missing={missing} attempt={attempt}/{MAX_RETRIES}"
                )

            resend = [pkt for pkt in pending_chunks if pkt["i"] in missing]
            if not resend:
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
ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=0.2)

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
# Step 1: Build logical session_init core
session_init_core = {
    "type": "session_init",
    "spacecraft_id": SPACECRAFT_ID,
    "session_id": session.session_id,
    "kem_ciphertext": b64e(kem_ciphertext),
}

# Step 2: Sign the logical session_init packet
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

# Step 4: Compress + base64 encode for chunking
session_init_b64, session_init_raw_len, session_init_comp_len = packet_to_base64_with_stats(
    session_init_packet
)

if DEBUG_PACKET_SIZES:
    print(
        f"[SAT] session_init sizes raw={session_init_raw_len} "
        f"compressed={session_init_comp_len}"
    )

# Step 5: Split into RF-safe chunks
session_init_chunks = make_chunk_packets(
    chunk_type="si",
    session_id=session.session_id,
    encoded_payload=session_init_b64,
    chunk_size=CHUNK_SIZE,
    message_id=None,
)

# Step 6: Send chunks
send_chunk_packets(ser, session_init_chunks)

print(
    f"[SAT] Sent session_init for session={session.session_id} "
    f"({len(session_init_chunks)} chunks)"
)

# Step 7: Wait for ACK/NACK
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
time.sleep(1)


# ---------------------------------------------------------------------
# Main telemetry loop
# ---------------------------------------------------------------------
while True:
    # -------------------------------------------------------------
    # Step 1: Generate simulated telemetry
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
    # Step 3: Convert frame to deterministic bytes
    # -------------------------------------------------------------
    frame_bytes = canonical_json_bytes(frame)

    # -------------------------------------------------------------
    # Step 4: Encrypt frame using AES-GCM session key
    # -------------------------------------------------------------
    encrypted = encrypt(
        frame_bytes,
        session.aes_key,
        aad=SPACECRAFT_ID.encode("utf-8"),
    )

    # -------------------------------------------------------------
    # Step 5: Build logical telemetry packet
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

    transmitted_packet = {
        **packet_core,
        "signature": b64e(telemetry_signature),
    }

    # -------------------------------------------------------------
    # Step 7: Compress + base64 encode for chunking
    # -------------------------------------------------------------
    telemetry_b64, telemetry_raw_len, telemetry_comp_len = packet_to_base64_with_stats(
        transmitted_packet
    )

    # -------------------------------------------------------------
    # Step 8: Split telemetry into RF-safe chunks
    # -------------------------------------------------------------
    telemetry_chunks = make_chunk_packets(
        chunk_type="tc",
        session_id=session.session_id,
        encoded_payload=telemetry_b64,
        chunk_size=CHUNK_SIZE,
        message_id=sequence,
    )

    # -------------------------------------------------------------
    # Step 9: Send telemetry chunks
    # -------------------------------------------------------------
    send_chunk_packets(ser, telemetry_chunks)

    if DEBUG_PACKET_SIZES:
        print(
            f"[SAT] TX secure packet "
            f"session={session.session_id} seq={sequence} "
            f"chunks={len(telemetry_chunks)} "
            f"raw={telemetry_raw_len} compressed={telemetry_comp_len} "
            f"payload={payload}"
        )
    else:
        print(
            f"[SAT] TX secure packet "
            f"session={session.session_id} seq={sequence} "
            f"chunks={len(telemetry_chunks)} payload={payload}"
        )

    # -------------------------------------------------------------
    # Step 10: Wait for ACK/NACK
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
    # Step 11: Move to next telemetry packet
    # -------------------------------------------------------------
    sequence += 1
    time.sleep(3)