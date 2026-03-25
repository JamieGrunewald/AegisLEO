"""
AegisLEO Ground Station Secure Receiver
Chunked RF Version with ACK/NACK Reassembly Control

Created by: Jamie Grunewald
Date: 2026-03-24
Version: v0.9.0

Purpose
-------
This script runs on the ground station and listens for incoming
secure telemetry packets from the satellite node.

What this version does
----------------------
1. Reads framed transport packets from the LoRa serial bridge
2. Reassembles chunked logical packets
3. Sends ACK when a full logical packet is reconstructed
4. Sends compact NACK for missing telemetry chunks
5. Verifies signatures on logical packets
6. Establishes ML-KEM session from session_init
7. Decrypts telemetry with AES-GCM
8. Applies replay protection
9. Runs anomaly detection
10. Prints a clean operator view

Why framing matters
-------------------
LoRa transparent serial links may:
- split packets
- merge packets
- inject stray bytes

So we do NOT trust newline boundaries anymore.

Instead, every transport packet is wrapped like:

    FRAME_START + JSON_BYTES + FRAME_END

The receiver scans the serial stream for those byte markers and only
tries to parse complete framed packets.
"""

from __future__ import annotations

import base64
import json
import time
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

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
DEBUG_CHUNKS = True
DEBUG_REASSEMBLY = True
DEBUG_ACKS = True
DEBUG_BAD_FRAMES = True

# How long to keep an incomplete chunk set before declaring it stale
REASSEMBLY_TTL_SECONDS = 5.0

# Transport frame markers
FRAME_START = b"\x7E"   # ~
FRAME_END = b"\x7F"


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

    def missing_indexes(self) -> list[int]:
        return [i for i in range(self.total_chunks) if i not in self.parts]

    def assemble(self) -> str:
        """
        Rebuild the original base64 payload in chunk order.
        """
        return "".join(self.parts[i] for i in range(self.total_chunks))


def b64text_to_packet(text: str) -> dict[str, Any]:
    """
    Convert an assembled base64 payload back into the original logical packet.

    Reverse order:
    1. base64 decode
    2. zlib decompress
    3. JSON decode
    """
    compressed = base64.b64decode(text.encode("utf-8"))
    raw = zlib.decompress(compressed)
    return json.loads(raw.decode("utf-8"))

# ---------------------------------------------------------------------
# Runtime objects
# ---------------------------------------------------------------------
ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=0.2)

key_manager = KeyManager()
detector = RuntimeDetector()

sessions: dict[str, object] = {}
replay_windows: dict[str, ReplayWindow] = {}

# Reassembly key:
#   (chunk_type, session_id, message_id)
reassembly_buffers: dict[tuple[str, str, int | None], ChunkAssembly] = {}

# Raw byte buffer used for frame extraction
serial_buffer = bytearray()

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
    Convert Unix timestamp to UTC string for clean operator display.
    """
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def packet_to_base64_with_stats(packet: dict[str, Any]) -> tuple[str, int, int]:
    """
    Same as packet_to_base64(), but also return original and compressed sizes.
    """
    raw = json.dumps(packet, separators=(",", ":")).encode("utf-8")
    compressed = zlib.compress(raw, level=9)
    encoded = base64.b64encode(compressed).decode("utf-8")
    return encoded, len(raw), len(compressed)


def write_framed_packet(pkt: dict[str, Any]) -> None:
    """
    Send one control-plane packet back to the transmitter with frame markers.
    """
    payload = json.dumps(pkt, separators=(",", ":")).encode("utf-8")
    wire = FRAME_START + payload + FRAME_END
    ser.write(wire)
    ser.flush()


def send_ack(session_id: str, message_id: int | None) -> None:
    """
    Tell the transmitter that a full logical packet was successfully reassembled.
    """
    pkt: dict[str, Any] = {"t": "ack", "sid": session_id}
    if message_id is not None:
        pkt["mid"] = message_id

    write_framed_packet(pkt)

    if DEBUG_ACKS:
        print(f"[GROUND][ACK] sid={session_id} mid={message_id}")


def send_nack(session_id: str, message_id: int | None, missing: list[int]) -> None:
    """
    Tell the transmitter which telemetry chunks are missing.

    We keep NACKs intentionally small so the NACK itself does not become
    another oversized RF message.
    """
    MAX_MISSING_PER_NACK = 16
    compact_missing = missing[:MAX_MISSING_PER_NACK]

    pkt: dict[str, Any] = {
        "t": "nack",
        "sid": session_id,
        "m": compact_missing,
    }
    if message_id is not None:
        pkt["mid"] = message_id

    write_framed_packet(pkt)

    if DEBUG_ACKS:
        print(f"[GROUND][NACK] sid={session_id} mid={message_id} missing={compact_missing}")


def cleanup_reassembly_buffers() -> None:
    """
    Remove stale incomplete chunk sets.

    Policy
    ------
    - session_init (mid is None):
      Do NOT send NACK. Let the transmitter timeout and resend the whole thing.
    - telemetry (mid is an int):
      Send a compact NACK for a small batch of missing chunk indexes.
    """
    now = time.time()
    stale_keys: list[tuple[str, str, int | None]] = []

    for key, buf in reassembly_buffers.items():
        age = now - buf.created_at
        if age > REASSEMBLY_TTL_SECONDS and not buf.is_complete():
            stale_keys.append(key)

    for key in stale_keys:
        _, session_id, message_id = key
        buf = reassembly_buffers[key]
        missing = buf.missing_indexes()

        if message_id is None:
            if DEBUG_ACKS:
                print(
                    f"[GROUND][INFO] stale session_init sid={session_id} "
                    f"missing_count={len(missing)} -> waiting for full resend"
                )
            del reassembly_buffers[key]
            continue

        send_nack(session_id, message_id, missing)

        # Keep already-received chunks, but refresh timer
        new_buf = ChunkAssembly(total_chunks=buf.total_chunks)
        new_buf.parts = dict(buf.parts)
        reassembly_buffers[key] = new_buf


def add_transport_chunk(packet: dict[str, Any]) -> dict[str, Any] | None:
    """
    Add one transport chunk to its reassembly bucket.

    Returns the full logical packet once complete.
    Otherwise returns None.
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
            f"[GROUND][CHUNK] t={chunk_type} sid={session_id} "
            f"mid={message_id} idx={chunk_index}/{chunk_total - 1}"
        )

    if not buf.is_complete():
        return None

    assembled_b64 = buf.assemble()
    del reassembly_buffers[key]

    if DEBUG_REASSEMBLY:
        print(
            f"[GROUND][REASSEMBLED] t={chunk_type} sid={session_id} "
            f"mid={message_id} len={len(assembled_b64)}"
        )

    # Logical packet reconstructed: ACK immediately
    send_ack(session_id, message_id)

    return b64text_to_packet(assembled_b64)


def extract_framed_packets(buffer: bytearray) -> list[bytes]:
    """
    Pull as many complete framed packets as possible out of the raw byte buffer.

    Framing format
    --------------
    FRAME_START + JSON_BYTES + FRAME_END
    """
    frames: list[bytes] = []

    while True:
        start = buffer.find(FRAME_START)
        if start == -1:
            # No frame start at all, drop noise
            buffer.clear()
            break

        # Drop anything before the next valid frame start
        if start > 0:
            del buffer[:start]

        end = buffer.find(FRAME_END, 1)
        if end == -1:
            # Incomplete frame, wait for more bytes
            break

        frame = bytes(buffer[1:end])
        del buffer[:end + 1]
        frames.append(frame)

    return frames


# ---------------------------------------------------------------------
# Main receive loop
# ---------------------------------------------------------------------
while True:
    try:
        incoming = ser.read(256)

        if incoming:
            serial_buffer.extend(incoming)
        else:
            cleanup_reassembly_buffers()
            continue

        frames = extract_framed_packets(serial_buffer)

        for frame_bytes in frames:
            try:
                text = frame_bytes.decode("utf-8", errors="ignore").strip()
                if not text:
                    continue

                transport_packet = json.loads(text)
            except json.JSONDecodeError:
                if DEBUG_BAD_FRAMES:
                    print(f"[GROUND] WARN: invalid framed JSON: {frame_bytes[:80]!r}")
                continue

            # Ignore control packets if they loop back or appear on RX side
            if transport_packet.get("t") in {"ack", "nack"}:
                continue

            # ---------------------------------------------------------
            # Step 1: Reassemble transport chunks into full logical packet
            # ---------------------------------------------------------
            packet = add_transport_chunk(transport_packet)
            if packet is None:
                continue

            packet_type = packet.get("type")

            # =========================================================
            # SESSION INIT
            # =========================================================
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
                    print("[GROUND] REJECTED: session_init signature invalid")
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

            # =========================================================
            # TELEMETRY
            # =========================================================
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
                print("[GROUND] REJECTED: telemetry signature invalid")
                continue

            session_id = packet["session_id"]

            if session_id not in sessions:
                print(f"[GROUND] WARN: telemetry before session ({session_id})")
                continue

            session = sessions[session_id]
            replay_window = replay_windows[session_id]

            if session.is_expired():
                print(f"[GROUND] REJECTED: session expired ({session_id})")
                continue

            # ---------------------------------------------------------
            # Step 2: Decrypt logical telemetry packet
            # ---------------------------------------------------------
            plaintext = decrypt(
                b64d(packet["nonce"]),
                b64d(packet["ciphertext"]),
                session.aes_key,
                aad=packet["spacecraft_id"].encode("utf-8"),
            )

            # ---------------------------------------------------------
            # Step 3: Parse decrypted CCSDS-inspired frame
            # ---------------------------------------------------------
            frame = parse_json_bytes(plaintext)

            # ---------------------------------------------------------
            # Step 4: Replay protection
            # ---------------------------------------------------------
            sequence = int(frame["sequence"])

            decision = replay_window.check(sequence)
            if not decision.accepted:
                print(
                    f"[GROUND] REJECTED: replay blocked "
                    f"(session={session_id}, seq={sequence}, reason={decision.reason})"
                )
                continue

            previous_max = replay_window.max_seq
            replay_window.record(sequence)

            # ---------------------------------------------------------
            # Step 5: Compute packet gap for operator visibility
            # ---------------------------------------------------------
            gap = 0
            if previous_max != -1 and sequence > previous_max + 1:
                gap = sequence - previous_max - 1

            # ---------------------------------------------------------
            # Step 6: Run anomaly detection
            # ---------------------------------------------------------
            detection = detector.detect(frame)

            # ---------------------------------------------------------
            # Step 7: Print operator view
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
        print(f"[GROUND] WARN: {exc}")