"""
AegisLEO Ground Station Secure Receiver
Transport-Hardened RF Version with Selective Recovery for session_init

Created by: Jamie Grunewald
Date: 2026-03-26
Version: v0.13.0

What changed in v0.13.0
-----------------------
1. Standardized demo logging with banner / kv / dlog helpers
2. Removed stray embedded docstring inside telemetry processing path
3. Added human-readable Telemetry object for stage output
4. Preserved ciphertext-before-plaintext proof view
5. Kept transport framing / reassembly / ACK/NACK behavior stable
6. Added clearer comments for learning and presentation use
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

from common.demo_log import (
    banner,
    dlog,
    kv,
    section,
    crypto_verdict,
    ml_verdict,
)
from common.telemetry import Telemetry

# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------

SERIAL_PORT = "/dev/serial/by-id/usb-1a86_USB_Single_Serial_5AAF186928-if00"
BAUD_RATE = 115200

MLDSA_ALGORITHM = "ML-DSA-65"

SATELLITE_MLDSA_PUBLIC_KEY_PATH = "keys/satellite_mldsa_public.key"
RECEIVER_KEM_PRIVATE_KEY_PATH = "dev_secrets/groundstation/receiver_kem_private.key"

# Frame layout:
#   FRAME_START (1 byte)
#   LENGTH      (4 bytes, big-endian)
#   PAYLOAD     (LENGTH bytes)
#   FRAME_END   (1 byte)
FRAME_START = b"\x7E"
FRAME_END = b"\x7F"
FRAME_LEN_BYTES = 4

# Maximum JSON payload size inside one transport frame.
MAX_FRAME_JSON_BYTES = 4096

TELEMETRY_TTL_SECONDS = 8.0
SESSION_INIT_TTL_SECONDS = 25

MAX_MISSING_PER_NACK = 24

DEBUG_SHOW_CIPHERTEXT = True
CIPHERTEXT_PREVIEW_LEN = 96

DEBUG_CHUNKS = True
DEBUG_REASSEMBLY = True
DEBUG_ACKS = True
DEBUG_BAD_FRAMES = True
DEBUG_SCHEMA = True

# ---------------------------------------------------------------------
# Transport / Link Counters
# ---------------------------------------------------------------------
STATS = {
    "frames_total": 0,
    "frames_utf8_fail": 0,
    "frames_json_fail": 0,
    "frames_bad_length": 0,
    "frames_bad_end_marker": 0,
    "chunks_total": 0,
    "chunks_crc_fail": 0,
    "chunks_duplicate": 0,
    "chunks_conflict": 0,
    "chunks_accepted": 0,
    "reassembly_complete": 0,
}

STATS_LAST_PRINT = time.time()
STATS_PRINT_INTERVAL = 5.0

# ---------------------------------------------------------------------
# Load key material
# ---------------------------------------------------------------------
with open(SATELLITE_MLDSA_PUBLIC_KEY_PATH, "rb") as f:
    SATELLITE_MLDSA_PUBLIC_KEY = f.read()

with open(RECEIVER_KEM_PRIVATE_KEY_PATH, "rb") as f:
    RECEIVER_KEM_PRIVATE_KEY = f.read()

# ---------------------------------------------------------------------
# Reassembly helper class
# ---------------------------------------------------------------------


@dataclass
class ChunkAssembly:
    """
    Hold pieces of one logical packet while chunks arrive.
    """

    total_chunks: int
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    parts: dict[int, str] = field(default_factory=dict)

    def add_part(self, idx: int, data: str) -> tuple[bool, bool]:
        """
        Returns
        -------
        (accepted_duplicate, conflicting_duplicate)
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


# ---------------------------------------------------------------------
# Decode the finished logical packet
# ---------------------------------------------------------------------


def b64text_to_packet(text: str) -> dict[str, Any]:
    """
    Reverse the sender-side logical packet pipeline:
    1. base64 decode
    2. zlib decompress
    3. JSON decode
    """
    compressed = base64.b64decode(text.encode("utf-8"), validate=True)
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
reassembly_buffers: dict[tuple[str, str, int | None], ChunkAssembly] = {}

# Raw serial byte buffer. Incomplete data stays here until a full frame exists.
serial_buffer = bytearray()

banner("AegisLEO Ground Station Secure Receiver")
kv("Serial port", SERIAL_PORT)
kv("Baud rate", BAUD_RATE)
kv("KEM alg", key_manager.algorithm)
print("Press Ctrl+C to stop.", flush=True)


# ---------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------


def pretty_time(epoch: int | float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def print_stats() -> None:
    global STATS_LAST_PRINT

    now = time.time()
    if now - STATS_LAST_PRINT < STATS_PRINT_INTERVAL:
        return

    STATS_LAST_PRINT = now

    dlog(
        "GROUND",
        "STATS",
        "Transport counters",
        frames=STATS["frames_total"],
        utf8_fail=STATS["frames_utf8_fail"],
        json_fail=STATS["frames_json_fail"],
        bad_len=STATS["frames_bad_length"],
        bad_end=STATS["frames_bad_end_marker"],
        chunks=STATS["chunks_total"],
        ok=STATS["chunks_accepted"],
        dup=STATS["chunks_duplicate"],
        crc_fail=STATS["chunks_crc_fail"],
        conflict=STATS["chunks_conflict"],
        reassembled=STATS["reassembly_complete"],
    )


def write_framed_packet(pkt: dict[str, Any]) -> None:
    """
    Send one ACK/NACK control packet back to the satellite using
    the length-prefixed framing format.

    Frame format:
        [FRAME_START][LEN:4][PAYLOAD][FRAME_END]
    """
    payload = json.dumps(pkt, separators=(",", ":")).encode("utf-8")
    length = len(payload).to_bytes(4, "big")
    wire = FRAME_START + length + payload + FRAME_END
    ser.write(wire)
    ser.flush()
    time.sleep(0.05)


def send_ack(session_id: str, message_id: int | None) -> None:
    pkt: dict[str, Any] = {"t": "ack", "sid": session_id}
    if message_id is not None:
        pkt["mid"] = message_id

    write_framed_packet(pkt)

    if DEBUG_ACKS:
        dlog("GROUND", "ACK", "Sent ACK to satellite", sid=session_id, mid=message_id)


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
        dlog(
            "GROUND",
            "NACK",
            "Sent NACK to satellite",
            sid=session_id,
            mid=message_id,
            missing=compact_missing,
        )


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

        label = "session_init" if message_id is None else "telemetry"
        dlog(
            "GROUND",
            "RECOVERY",
            "Stale partial assembly detected",
            kind=label,
            sid=session_id,
            mid=message_id,
            have=f"{len(buf.parts)}/{buf.total_chunks}",
            missing_count=len(missing),
        )

        if len(missing) <= 10:
            dlog(
                "GROUND",
                "RECOVERY_DETAIL",
                "Missing indexes still required",
                sid=session_id,
                mid=message_id,
                missing=missing,
            )

        send_nack(session_id=session_id, message_id=message_id, missing=missing)

        # Keep any chunks we already have, but refresh the assembly timer.
        new_buf = ChunkAssembly(total_chunks=buf.total_chunks)
        new_buf.parts = dict(buf.parts)
        new_buf.updated_at = time.time()
        reassembly_buffers[key] = new_buf


def validate_transport_packet(packet: dict[str, Any]) -> bool:
    """
    Validate the outer transport packet before it enters the chunk
    reassembly pipeline.
    """
    packet_type = packet.get("t")

    if packet_type in {"ack", "nack"}:
        return True

    required = {"t", "sid", "i", "n", "d", "c"}
    if not required.issubset(packet):
        if DEBUG_SCHEMA:
            dlog("GROUND", "SCHEMA", "Missing keys in transport packet", packet=packet)
        return False

    if packet_type not in {"si", "tc"}:
        if DEBUG_SCHEMA:
            dlog("GROUND", "SCHEMA", "Invalid transport packet type", t=packet_type)
        return False

    if not isinstance(packet["sid"], str) or not packet["sid"]:
        return False

    if not isinstance(packet["d"], str) or not packet["d"]:
        return False

    try:
        idx = int(packet["i"])
        total = int(packet["n"])
        crc = int(packet["c"])
    except (TypeError, ValueError):
        return False

    if total <= 0:
        return False

    if idx < 0 or idx >= total:
        return False

    if crc < 0 or crc > 0xFFFFFFFF:
        return False

    if packet_type == "tc" and "mid" not in packet:
        return False

    return True


def add_transport_chunk(packet: dict[str, Any]) -> tuple[str, int | None, str] | None:
    """
    Add one validated transport chunk to the proper reassembly buffer.
    """
    cleanup_reassembly_buffers()

    chunk_type = packet["t"]
    session_id = packet["sid"]
    message_id = packet.get("mid")
    chunk_index = int(packet["i"])
    chunk_total = int(packet["n"])
    data_fragment = packet["d"]

    STATS["chunks_total"] += 1

    expected_crc = int(packet["c"])
    actual_crc = zlib.crc32(data_fragment.encode("utf-8")) & 0xFFFFFFFF

    if actual_crc != expected_crc:
        STATS["chunks_crc_fail"] += 1
        dlog(
            "GROUND",
            "CRC_FAIL",
            "Chunk CRC mismatch",
            sid=session_id,
            mid=message_id,
            idx=chunk_index,
            expected=f"{expected_crc:#010x}",
            actual=f"{actual_crc:#010x}",
        )
        return None

    key = (chunk_type, session_id, message_id)

    if key not in reassembly_buffers:
        reassembly_buffers[key] = ChunkAssembly(total_chunks=chunk_total)

    buf = reassembly_buffers[key]

    if buf.total_chunks != chunk_total:
        if DEBUG_SCHEMA:
            dlog(
                "GROUND",
                "SCHEMA",
                "Chunk total mismatch, resetting assembly",
                sid=session_id,
                mid=message_id,
                old_total=buf.total_chunks,
                new_total=chunk_total,
            )
        del reassembly_buffers[key]
        return None

    accepted_duplicate, conflicting_duplicate = buf.add_part(chunk_index, data_fragment)

    if accepted_duplicate:
        STATS["chunks_duplicate"] += 1

    if conflicting_duplicate:
        STATS["chunks_conflict"] += 1
        dlog(
            "GROUND",
            "WARN",
            "Conflicting duplicate chunk detected, resetting assembly",
            sid=session_id,
            mid=message_id,
            idx=chunk_index,
        )
        del reassembly_buffers[key]
        return None

    if not accepted_duplicate:
        STATS["chunks_accepted"] += 1

    if DEBUG_CHUNKS:
        dlog(
            "GROUND",
            "CHUNK_RX",
            "Chunk accepted",
            t=chunk_type,
            sid=session_id,
            mid=message_id,
            idx=f"{chunk_index}/{chunk_total - 1}",
            dup=accepted_duplicate,
        )

    if DEBUG_REASSEMBLY:
        dlog(
            "GROUND",
            "REASSEMBLY",
            "Chunk progress",
            sid=session_id,
            mid=message_id,
            have=f"{len(buf.parts)}/{buf.total_chunks}",
        )

    if not buf.is_complete():
        return None

    assembled_b64 = buf.assemble()
    del reassembly_buffers[key]

    STATS["reassembly_complete"] += 1

    if DEBUG_REASSEMBLY:
        dlog(
            "GROUND",
            "REASSEMBLED",
            "Logical packet fully reassembled",
            t=chunk_type,
            sid=session_id,
            mid=message_id,
            length=len(assembled_b64),
        )

    return session_id, message_id, assembled_b64


def extract_framed_packets(buffer: bytearray) -> list[bytes]:
    """
    Extract complete length-prefixed frames from the raw serial buffer.

    Frame format:
        [FRAME_START][LEN:4][PAYLOAD][FRAME_END]
    """
    frames: list[bytes] = []

    while True:
        start = buffer.find(FRAME_START)

        if start == -1:
            buffer.clear()
            break

        if start > 0:
            del buffer[:start]

        if len(buffer) < 1 + FRAME_LEN_BYTES:
            break

        if buffer[0:1] != FRAME_START:
            del buffer[0]
            continue

        payload_len = int.from_bytes(buffer[1:5], "big")

        if payload_len <= 0 or payload_len > MAX_FRAME_JSON_BYTES:
            STATS["frames_bad_length"] += 1
            if DEBUG_BAD_FRAMES:
                dlog(
                    "GROUND",
                    "WARN",
                    "Invalid frame length, dropping 1 byte to resync",
                    payload_len=payload_len,
                )
            del buffer[0]
            continue

        total_len = 1 + 4 + payload_len + 1

        if len(buffer) < total_len:
            break

        payload = bytes(buffer[5:5 + payload_len])
        end_marker = buffer[5 + payload_len:5 + payload_len + 1]

        if end_marker != FRAME_END:
            STATS["frames_bad_end_marker"] += 1
            if DEBUG_BAD_FRAMES and STATS["frames_bad_end_marker"] % 10 == 0:
                dlog(
                    "GROUND",
                    "WARN",
                    "Bad frame end marker, dropping 1 byte to resync",
                    end_marker=repr(end_marker),
                    count=STATS["frames_bad_end_marker"],
                )
            del buffer[0]
            continue

        del buffer[:total_len]
        frames.append(payload)

    return frames


# ---------------------------------------------------------------------
# Main receive loop
# ---------------------------------------------------------------------
while True:
    try:
        incoming = ser.read(2048)

        if incoming:
            serial_buffer.extend(incoming)
        else:
            cleanup_reassembly_buffers()
            print_stats()
            continue

        frames = extract_framed_packets(serial_buffer)

        for frame_bytes in frames:
            STATS["frames_total"] += 1

            try:
                # Transport packets should be JSON objects, so raw payload
                # should begin with "{".
                if not frame_bytes.startswith(b"{"):
                    if DEBUG_BAD_FRAMES:
                        dlog("GROUND", "WARN", "Non-JSON frame dropped", preview=repr(frame_bytes[:80]))
                    STATS["frames_json_fail"] += 1
                    continue

                text = frame_bytes.decode("utf-8").strip()
                if not text:
                    continue

                transport_packet = json.loads(text)

            except UnicodeDecodeError:
                STATS["frames_utf8_fail"] += 1
                if DEBUG_BAD_FRAMES:
                    dlog("GROUND", "WARN", "Non-UTF8 frame dropped", preview=repr(frame_bytes[:80]))
                continue

            except json.JSONDecodeError:
                STATS["frames_json_fail"] += 1
                if DEBUG_BAD_FRAMES:
                    dlog("GROUND", "WARN", "Invalid framed JSON dropped", preview=repr(frame_bytes[:80]))
                continue

            if not validate_transport_packet(transport_packet):
                continue

            # Receiver ignores control packets arriving on RX path.
            if transport_packet.get("t") in {"ack", "nack"}:
                continue

            reassembled = add_transport_chunk(transport_packet)
            if reassembled is None:
                continue

            session_id, message_id, assembled_b64 = reassembled

            try:
                packet = b64text_to_packet(assembled_b64)
            except Exception as exc:
                dlog(
                    "GROUND",
                    "WARN",
                    "Logical packet decode failed",
                    sid=session_id,
                    mid=message_id,
                    error=str(exc),
                )
                send_nack(session_id=session_id, message_id=message_id, missing=list(range(0, 8)))
                continue

            packet_type = packet.get("type")

            # =========================================================
            # SESSION INIT
            # =========================================================
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
                        dlog("GROUND", "REJECT", "Session-init signature invalid", sid=session_id)
                        send_nack(session_id=session_id, message_id=message_id, missing=[0])
                        continue

                    session_id = packet["session_id"]

                    if session_id in sessions:
                        dlog("GROUND", "SESSION_EXISTS", "Session already exists", sid=session_id)
                        send_ack(session_id, message_id)
                        continue

                    dlog("GROUND", "SESSION_INIT_RX", "Received signed session-init", sid=session_id)

                    session = key_manager.create_receiver_session(
                        kem_ciphertext=b64d(packet["kem_ciphertext"]),
                        receiver_private_key=RECEIVER_KEM_PRIVATE_KEY,
                        session_id=session_id,
                    )

                    sessions[session_id] = session
                    replay_windows[session_id] = ReplayWindow(window_size=64)

                    dlog("GROUND", "SESSION_ESTABLISHED", "Receiver session established", sid=session_id)
                    send_ack(session_id, message_id)
                    continue

                except Exception as exc:
                    dlog(
                        "GROUND",
                        "REJECT",
                        "Session-init processing failed",
                        sid=session_id,
                        error=str(exc),
                    )
                    send_nack(session_id=session_id, message_id=message_id, missing=[0])
                    continue

            # =========================================================
            # TELEMETRY
            # =========================================================
            if packet_type != "telemetry":
                dlog("GROUND", "WARN", "Unknown logical packet type", packet_type=packet_type)
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
                    dlog("GROUND", "REJECT", "Telemetry signature invalid", sid=session_id, mid=message_id)
                    send_nack(session_id=session_id, message_id=message_id, missing=[0])
                    continue

                session_id = packet["session_id"]

                if session_id not in sessions:
                    dlog("GROUND", "WARN", "Telemetry arrived before session existed", sid=session_id, mid=message_id)
                    send_nack(session_id=session_id, message_id=message_id, missing=[0])
                    continue

                session = sessions[session_id]
                replay_window = replay_windows[session_id]

                if session.is_expired():
                    dlog("GROUND", "REJECT", "Session expired", sid=session_id, mid=message_id)
                    send_nack(session_id=session_id, message_id=message_id, missing=[0])
                    continue

                # -----------------------------------------------------
                # Ciphertext proof block
                # -----------------------------------------------------
                if DEBUG_SHOW_CIPHERTEXT:
                    ciphertext_b64 = packet["ciphertext"]
                    nonce_b64 = packet["nonce"]

                    section("Encrypted Telemetry View (before decrypt)")
                    kv("Algorithms", "ML-KEM-1024 + AES-GCM + ML-DSA-65")
                    kv("Session ID", packet["session_id"])
                    kv("Nonce", nonce_b64)
                    kv("Nonce len", f"{len(nonce_b64)} base64 chars")
                    kv(
                        "Ciphertext",
                        f"{ciphertext_b64[:CIPHERTEXT_PREVIEW_LEN]}"
                        f"{'...' if len(ciphertext_b64) > CIPHERTEXT_PREVIEW_LEN else ''}",
                    )
                    kv("CT length", f"{len(ciphertext_b64)} base64 chars")

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
                    dlog(
                        "GROUND",
                        "REJECT",
                        "Replay blocked",
                        session=session_id,
                        seq=sequence,
                        reason=decision.reason,
                    )
                    send_nack(session_id=session_id, message_id=message_id, missing=[0])
                    continue

                previous_max = replay_window.max_seq
                replay_window.record(sequence)

                gap = 0
                if previous_max != -1 and sequence > previous_max + 1:
                    gap = sequence - previous_max - 1

                detection = detector.detect(frame)
                payload = frame["payload"]

                # Convert decrypted payload into a richer human-readable telemetry object.
                telemetry = Telemetry(
                    seq=sequence,
                    timestamp=float(frame["timestamp"]),
                    temperature_c=float(payload["temp_c"]),
                    battery_pct=int(payload.get("battery_pct", 100)),
                    mode=str(payload["state"]),
                    latitude=float(payload.get("latitude", 0.0)),
                    longitude=float(payload.get("longitude", 0.0)),
                    altitude_km=float(payload.get("altitude_km", 0.0)),
                    bus_v=float(payload["bus_v"]),
                    bus_i=float(payload["bus_i"]),
                )

                dlog(
                    "GROUND",
                    "TELEMETRY_RX",
                    "Secure telemetry packet accepted",
                    seq=sequence,
                    session=session_id,
                    apid=frame["apid"],
                )

                if detection.is_anomalous:
                    dlog(
                        "GROUND",
                        "ML_ALERT",
                        "Anomalous telemetry detected",
                        seq=sequence,
                        score=detection.score,
                        reasons=detection.reasons,
                    )
                else:
                    dlog(
                        "GROUND",
                        "ML_OK",
                        "Telemetry classified as nominal",
                        seq=sequence,
                        score=detection.score,
                    )

                banner("AegisLEO Secure Telemetry Packet")
                kv("Spacecraft", frame["spacecraft_id"])
                kv("Session ID", session_id)
                kv("Timestamp", pretty_time(frame["timestamp"]))
                kv("APID", frame["apid"])
                kv("Sequence", sequence)
                kv("Gap", gap)
                kv("Replay", f"ACCEPTED ({decision.reason})")
                kv(
                    "Crypto",
                    crypto_verdict(
                        signature_valid=True,
                        session_active=True,
                        decrypt_ok=True,
                    ),
                )
                kv(
                    "ML",
                    ml_verdict(
                        detection.is_anomalous,
                        detection.score,
                        detection.reasons,
                    ),
                )
                kv("Proof", "ciphertext shown above, plaintext shown below after AES-GCM decrypt")

                section("Telemetry Operator View")
                for key, value in telemetry.operator_lines():
                    kv(key, value)

                section("Telemetry Summary")
                print(telemetry.summary(), flush=True)

                send_ack(session_id, message_id)

            except Exception as exc:
                dlog(
                    "GROUND",
                    "REJECT",
                    "Telemetry processing failed",
                    sid=session_id,
                    mid=message_id,
                    error=str(exc),
                )
                send_nack(session_id=session_id, message_id=message_id, missing=[0])

        print_stats()

    except Exception as exc:
        dlog("GROUND", "WARN", "Top-level receiver loop exception", error=str(exc))