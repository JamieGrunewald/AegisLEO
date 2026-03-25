"""
AegisLEO Ground Station Secure Receiver
Transport-Hardened RF Version with Selective Recovery for session_init

Created by: Jamie Grunewald
Updated by: OpenAI ChatGPT
Date: 2026-03-25
Version: v0.11.1

v0.11.1 patch notes
-------------------
1. ACK moved later so we only ACK after logical packet success
2. session_init now supports selective NACK recovery
3. duplicate chunk handling added
4. reassembly progress logging added
5. stricter UTF-8 frame parsing restored
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

FRAME_START = b"\x7E"
FRAME_END = b"\x7F"

MAX_FRAME_JSON_BYTES = 768

TELEMETRY_TTL_SECONDS = 8.0
SESSION_INIT_TTL_SECONDS = 60.0

MAX_MISSING_PER_NACK = 24

DEBUG_CHUNKS = True
DEBUG_REASSEMBLY = True
DEBUG_ACKS = True
DEBUG_BAD_FRAMES = True
DEBUG_SCHEMA = True

with open(SATELLITE_MLDSA_PUBLIC_KEY_PATH, "rb") as f:
    SATELLITE_MLDSA_PUBLIC_KEY = f.read()

with open(RECEIVER_KEM_PRIVATE_KEY_PATH, "rb") as f:
    RECEIVER_KEM_PRIVATE_KEY = f.read()


@dataclass
class ChunkAssembly:
    total_chunks: int
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    parts: dict[int, str] = field(default_factory=dict)

    def add_part(self, idx: int, data: str) -> tuple[bool, bool]:
        """
        Returns:
            accepted_duplicate, conflicting_duplicate
        """
        existing = self.parts.get(idx)
        if existing is not None:
            if existing == data:
                self.updated_at = time.time()
                return True, False
            return False, True

        self.parts[idx] = data
        self.updated_at = time.time()
        return False, False

    def is_complete(self) -> bool:
        return len(self.parts) == self.total_chunks

    def missing_indexes(self) -> list[int]:
        return [i for i in range(self.total_chunks) if i not in self.parts]

    def assemble(self) -> str:
        return "".join(self.parts[i] for i in range(self.total_chunks))


def b64text_to_packet(text: str) -> dict[str, Any]:
    compressed = base64.b64decode(text.encode("utf-8"), validate=True)
    raw = zlib.decompress(compressed)
    return json.loads(raw.decode("utf-8"))


ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=0.2)

key_manager = KeyManager()
detector = RuntimeDetector()

sessions: dict[str, object] = {}
replay_windows: dict[str, ReplayWindow] = {}
reassembly_buffers: dict[tuple[str, str, int | None], ChunkAssembly] = {}
serial_buffer = bytearray()

print("Ground station secure receiver online")
print(f"Serial port: {SERIAL_PORT}")
print(f"Baud rate  : {BAUD_RATE}")
print(f"KEM alg    : {key_manager.algorithm}")
print("Press Ctrl+C to stop.")


def pretty_time(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def write_framed_packet(pkt: dict[str, Any]) -> None:
    payload = json.dumps(pkt, separators=(",", ":")).encode("utf-8")
    wire = FRAME_START + payload + FRAME_END
    ser.write(wire)
    ser.flush()


def send_ack(session_id: str, message_id: int | None) -> None:
    pkt: dict[str, Any] = {"t": "ack", "sid": session_id}
    if message_id is not None:
        pkt["mid"] = message_id
    write_framed_packet(pkt)
    if DEBUG_ACKS:
        print(f"[GROUND][ACK] sid={session_id} mid={message_id}")


def send_nack(session_id: str, missing: list[int], message_id: int | None = None) -> None:
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


def get_reassembly_ttl(message_id: int | None) -> float:
    return SESSION_INIT_TTL_SECONDS if message_id is None else TELEMETRY_TTL_SECONDS


def cleanup_reassembly_buffers() -> None:
    now = time.time()
    stale_keys: list[tuple[str, str, int | None]] = []

    for key, buf in reassembly_buffers.items():
        _, _, message_id = key
        ttl = get_reassembly_ttl(message_id)
        age = now - buf.updated_at
        if age > ttl and not buf.is_complete():
            stale_keys.append(key)

    for key in stale_keys:
        _, session_id, message_id = key
        buf = reassembly_buffers[key]
        missing = buf.missing_indexes()

        if DEBUG_ACKS:
            label = "session_init" if message_id is None else "telemetry"
            print(
                f"[GROUND][INFO] stale {label} sid={session_id} mid={message_id} "
                f"have={len(buf.parts)}/{buf.total_chunks} missing_count={len(missing)}"
            )

        send_nack(session_id=session_id, message_id=message_id, missing=missing)

        new_buf = ChunkAssembly(total_chunks=buf.total_chunks)
        new_buf.parts = dict(buf.parts)
        new_buf.updated_at = time.time()
        reassembly_buffers[key] = new_buf


def validate_transport_packet(packet: dict[str, Any]) -> bool:
    packet_type = packet.get("t")

    if packet_type in {"ack", "nack"}:
        return True

    required = {"t", "sid", "i", "n", "d"}
    if not required.issubset(packet):
        if DEBUG_SCHEMA:
            print(f"[GROUND][SCHEMA] missing keys in transport packet: {packet}")
        return False

    if packet_type not in {"si", "tc"}:
        if DEBUG_SCHEMA:
            print(f"[GROUND][SCHEMA] invalid transport type: {packet_type}")
        return False

    if not isinstance(packet["sid"], str) or not packet["sid"]:
        return False
    if not isinstance(packet["d"], str) or not packet["d"]:
        return False

    try:
        idx = int(packet["i"])
        total = int(packet["n"])
    except (TypeError, ValueError):
        return False

    if total <= 0:
        return False
    if idx < 0 or idx >= total:
        return False
    if packet_type == "tc" and "mid" not in packet:
        return False

    return True


def add_transport_chunk(packet: dict[str, Any]) -> tuple[str, int | None, str] | None:
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

    if buf.total_chunks != chunk_total:
        if DEBUG_SCHEMA:
            print(
                f"[GROUND][SCHEMA] chunk total mismatch sid={session_id} "
                f"mid={message_id} old_total={buf.total_chunks} new_total={chunk_total}"
            )
        del reassembly_buffers[key]
        return None

    accepted_duplicate, conflicting_duplicate = buf.add_part(chunk_index, data_fragment)

    if conflicting_duplicate:
        print(
            f"[GROUND][WARN] conflicting duplicate chunk sid={session_id} "
            f"mid={message_id} idx={chunk_index} -> resetting assembly"
        )
        del reassembly_buffers[key]
        return None

    if DEBUG_CHUNKS:
        suffix = " DUP" if accepted_duplicate else ""
        print(
            f"[GROUND][CHUNK] t={chunk_type} sid={session_id} "
            f"mid={message_id} idx={chunk_index}/{chunk_total - 1}{suffix}"
        )

    if DEBUG_REASSEMBLY:
        print(
            f"[GROUND][REASSEMBLY] sid={session_id} mid={message_id} "
            f"have={len(buf.parts)}/{buf.total_chunks}"
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

    return session_id, message_id, assembled_b64


def extract_framed_packets(buffer: bytearray) -> list[bytes]:
    frames: list[bytes] = []

    while True:
        start = buffer.find(FRAME_START)
        if start == -1:
            buffer.clear()
            break

        if start > 0:
            del buffer[:start]

        end = buffer.find(FRAME_END, 1)
        if end == -1:
            if len(buffer) > MAX_FRAME_JSON_BYTES + 2:
                del buffer[0]
            break

        frame = bytes(buffer[1:end])
        del buffer[:end + 1]

        if not frame:
            continue

        if len(frame) > MAX_FRAME_JSON_BYTES:
            if DEBUG_BAD_FRAMES:
                print(f"[GROUND] WARN: oversized frame dropped ({len(frame)} bytes)")
            continue

        frames.append(frame)

    return frames


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
                text = frame_bytes.decode("utf-8").strip()
                if not text:
                    continue
                transport_packet = json.loads(text)
            except UnicodeDecodeError:
                if DEBUG_BAD_FRAMES:
                    print(f"[GROUND] WARN: non-UTF8 frame dropped: {frame_bytes[:80]!r}")
                continue
            except json.JSONDecodeError:
                if DEBUG_BAD_FRAMES:
                    print(f"[GROUND] WARN: invalid framed JSON: {frame_bytes[:80]!r}")
                continue

            if not validate_transport_packet(transport_packet):
                continue

            if transport_packet.get("t") in {"ack", "nack"}:
                continue

            reassembled = add_transport_chunk(transport_packet)
            if reassembled is None:
                continue

            session_id, message_id, assembled_b64 = reassembled

            try:
                packet = b64text_to_packet(assembled_b64)
            except Exception as exc:
                print(
                    f"[GROUND] WARN: logical packet decode failed "
                    f"sid={session_id} mid={message_id}: {exc}"
                )
                send_nack(session_id=session_id, message_id=message_id, missing=list(range(0, 8)))
                continue

            packet_type = packet.get("type")

            if packet_type == "session_init":
                try:
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
                        send_nack(session_id=session_id, message_id=message_id, missing=[0])
                        continue

                    session_id = packet["session_id"]

                    if session_id in sessions:
                        print(f"[GROUND] INFO: session already exists ({session_id})")
                        send_ack(session_id, message_id)
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
                    send_ack(session_id, message_id)
                    continue
                except Exception as exc:
                    print(f"[GROUND] REJECTED: session_init processing failed: {exc}")
                    send_nack(session_id=session_id, message_id=message_id, missing=[0])
                    continue

            if packet_type != "telemetry":
                print(f"[GROUND] WARN: unknown logical packet type: {packet_type}")
                send_nack(session_id=session_id, message_id=message_id, missing=[0])
                continue

            try:
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
                    send_nack(session_id=session_id, message_id=message_id, missing=[0])
                    continue

                session_id = packet["session_id"]

                if session_id not in sessions:
                    print(f"[GROUND] WARN: telemetry before session ({session_id})")
                    send_nack(session_id=session_id, message_id=message_id, missing=[0])
                    continue

                session = sessions[session_id]
                replay_window = replay_windows[session_id]

                if session.is_expired():
                    print(f"[GROUND] REJECTED: session expired ({session_id})")
                    send_nack(session_id=session_id, message_id=message_id, missing=[0])
                    continue

                plaintext = decrypt(
                    b64d(packet["nonce"]),
                    b64d(packet["ciphertext"]),
                    session.aes_key,
                    aad=packet["spacecraft_id"].encode("utf-8"),
                )

                frame = parse_json_bytes(plaintext)

                sequence = int(frame["sequence"])

                decision = replay_window.check(sequence)
                if not decision.accepted:
                    print(
                        f"[GROUND] REJECTED: replay blocked "
                        f"(session={session_id}, seq={sequence}, reason={decision.reason})"
                    )
                    send_nack(session_id=session_id, message_id=message_id, missing=[0])
                    continue

                previous_max = replay_window.max_seq
                replay_window.record(sequence)

                gap = 0
                if previous_max != -1 and sequence > previous_max + 1:
                    gap = sequence - previous_max - 1

                detection = detector.detect(frame)

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

                payload = frame["payload"]
                print(
                    f"Payload    : temp_c={payload['temp_c']} "
                    f"bus_v={payload['bus_v']} "
                    f"bus_i={payload['bus_i']} "
                    f"state={payload['state']}"
                )
                print("=" * 72)

                send_ack(session_id, message_id)

            except Exception as exc:
                print(f"[GROUND] REJECTED: telemetry processing failed sid={session_id} mid={message_id}: {exc}")
                send_nack(session_id=session_id, message_id=message_id, missing=[0])

    except Exception as exc:
        print(f"[GROUND] WARN: {exc}")