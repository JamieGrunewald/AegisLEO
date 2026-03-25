"""
AegisLEO Ground Station Secure Receiver (Chunked RF Version)

Created by: Jamie Grunewald
Date: 2026-03-24
Version: v0.7.0

Purpose
-------
This script runs on the ground station and listens for incoming
secure telemetry packets from the satellite node.

What this receiver does
-----------------------
1. Read small transport chunks from the LoRa serial bridge
2. Reassemble those chunks into full logical packets
3. Handle a signed session_init packet
4. Handle signed, encrypted telemetry packets
5. Decrypt telemetry using the established session AES key
6. Parse telemetry frame
7. Apply replay protection
8. Run anomaly detection
9. Print a clean operator view

Why this version matters
------------------------
LoRa transparent serial links do not reliably carry large JSON packets as
single units. So this receiver reconstructs them from smaller RF-safe chunks.

Transport chunk types
---------------------
si -> session_init chunk
tc -> telemetry chunk

Important note
--------------
The security model is preserved at the logical-packet layer:
- session_init is still signed
- telemetry is still signed
- telemetry payload is still encrypted with AES-GCM

Chunking only changes transport format, not core security intent.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
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

# Debug controls
DEBUG_SERIAL = False
DEBUG_CHUNKS = False
DEBUG_REASSEMBLY = False

# Drop incomplete chunk sets after this many seconds
REASSEMBLY_TTL_SECONDS = 30


# ---------------------------------------------------------------------
# Load key material
# ---------------------------------------------------------------------
with open(SATELLITE_MLDSA_PUBLIC_KEY_PATH, "rb") as f:
    SATELLITE_MLDSA_PUBLIC_KEY = f.read()

with open(RECEIVER_KEM_PRIVATE_KEY_PATH, "rb") as f:
    RECEIVER_KEM_PRIVATE_KEY = f.read()


# ---------------------------------------------------------------------
# Reassembly helpers
# ---------------------------------------------------------------------
@dataclass
class ChunkAssembly:
    """
    Hold the pieces of one logical packet while chunks arrive.
    """
    total_chunks: int
    created_at: float = field(default_factory=time.time)
    parts: dict[int, str] = field(default_factory=dict)

    def add_part(self, idx: int, data: str) -> None:
        self.parts[idx] = data

    def is_complete(self) -> bool:
        return len(self.parts) == self.total_chunks

    def assemble(self) -> str:
        """
        Rebuild the original base64 payload in order.
        """
        return "".join(self.parts[i] for i in range(self.total_chunks))


def b64text_to_packet(text: str) -> dict:
    """
    Convert the assembled base64 text back into the original logical packet.
    """
    raw = base64.b64decode(text.encode("utf-8"))
    return json.loads(raw.decode("utf-8"))


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

# reassembly_buffers[(chunk_type, session_id, message_id)] -> ChunkAssembly
reassembly_buffers: dict[tuple[str, str, int | None], ChunkAssembly] = {}

# JSON decoder for small transport chunk packets
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
    Try to peel one JSON object off the front/middle of a text buffer.

    Why this exists
    ---------------
    The serial bridge may still hand us:
    - one clean chunk packet
    - multiple chunk packets at once
    - leading junk before a '{'

    So we find the first '{' and ask the JSON decoder to parse one object.
    """
    start = buffer.find("{")
    if start == -1:
        return None, ""

    candidate = buffer[start:]

    try:
        packet, end_idx = decoder.raw_decode(candidate)
        remaining = candidate[end_idx:]
        return packet, remaining
    except json.JSONDecodeError:
        # Not enough data yet for one complete transport chunk packet
        return None, candidate


def cleanup_reassembly_buffers() -> None:
    """
    Remove stale incomplete chunk sets so memory does not grow forever.
    """
    now = time.time()
    stale_keys = [
        key for key, buf in reassembly_buffers.items()
        if now - buf.created_at > REASSEMBLY_TTL_SECONDS
    ]
    for key in stale_keys:
        del reassembly_buffers[key]


def add_transport_chunk(packet: dict) -> dict | None:
    """
    Add one transport chunk packet to the appropriate reassembly bucket.

    Returns
    -------
    dict | None
        The full logical packet when all chunks are present, else None.
    """
    cleanup_reassembly_buffers()

    chunk_type = packet["t"]
    session_id = packet["sid"]
    message_id = packet.get("mid")

    chunk_index = int(packet["i"])
    chunk_total = int(packet["n"])
    data_fragment = packet["d"]

    key = (chunk_type, session_id, message_id)

    if key not in reassembly_buffers:
        reassembly_buffers[key] = ChunkAssembly(total_chunks=chunk_total)

    buf = reassembly_buffers[key]
    buf.add_part(chunk_index, data_fragment)

    if DEBUG_CHUNKS:
        print(
            f"[DEBUG] CHUNK t={chunk_type} sid={session_id} "
            f"mid={message_id} idx={chunk_index}/{chunk_total - 1}"
        )

    if not buf.is_complete():
        return None

    assembled_b64 = buf.assemble()
    del reassembly_buffers[key]

    if DEBUG_REASSEMBLY:
        print(
            f"[DEBUG] REASSEMBLED t={chunk_type} sid={session_id} "
            f"mid={message_id} len={len(assembled_b64)}"
        )

    return b64text_to_packet(assembled_b64)


# ---------------------------------------------------------------------
# Main receive loop
# ---------------------------------------------------------------------
buffer = ""

while True:
    # Read serial bytes and append to rolling text buffer.
    chunk = ser.read(1024)

    if not chunk:
        continue

    if DEBUG_SERIAL:
        print(f"[DEBUG] RAW CHUNK: {repr(chunk[:120])}")

    buffer += chunk.decode("utf-8", errors="ignore")

    # Keep pulling out small transport chunk packets as they become available.
    while True:
        transport_packet, buffer = extract_next_json(buffer)

        if transport_packet is None:
            break

        try:
            # ---------------------------------------------------------
            # Step 1: Reassemble transport chunks into full logical packet
            # ---------------------------------------------------------
            packet = add_transport_chunk(transport_packet)

            # If packet is None, we do not have all chunks yet.
            if packet is None:
                continue

            packet_type = packet.get("type")

            # ---------------------------------------------------------
            # Step 2: Handle session_init logical packet
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
            # Step 3: Handle telemetry logical packet
            # ---------------------------------------------------------
            if packet_type != "telemetry":
                print(f"[GROUND] WARN: unknown logical packet type: {packet_type}")
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
            # Step 4: Decrypt telemetry payload
            # ---------------------------------------------------------
            plaintext = decrypt(
                b64d(packet["nonce"]),
                b64d(packet["ciphertext"]),
                session.aes_key,
                aad=packet["spacecraft_id"].encode("utf-8"),
            )

            # ---------------------------------------------------------
            # Step 5: Parse decrypted telemetry frame
            # ---------------------------------------------------------
            frame = parse_json_bytes(plaintext)

            # ---------------------------------------------------------
            # Step 6: Replay protection
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
            # Step 7: Compute packet gap
            # ---------------------------------------------------------
            gap = 0
            if previous_max != -1 and sequence > previous_max + 1:
                gap = sequence - previous_max - 1

            # ---------------------------------------------------------
            # Step 8: Run anomaly detection
            # ---------------------------------------------------------
            detection = detector.detect(frame)

            # ---------------------------------------------------------
            # Step 9: Print clean operator view
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