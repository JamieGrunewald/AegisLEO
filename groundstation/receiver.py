"""
AegisLEO Ground Station Secure Receiver
Transport-Hardened RF Version with Selective Recovery for session_init

Created by: Jamie Grunewald
Date: 2026-03-25
Version: v0.12.0

What this script does
---------------------
This script runs on the ground station and listens for secure telemetry
coming from the satellite node over the LoRa serial link.

High-level flow
---------------
1. Read framed transport packets from serial
2. Validate packet structure
3. Validate chunk CRC so corrupted chunks do not poison reassembly
4. Reassemble chunks into one full logical packet
5. Decode + verify signature + establish/decrypt session data
6. Apply replay protection
7. Run ML anomaly detection
8. Send ACK/NACK back to the satellite side

Framing upgrade in this version
-------------------------------
Old framing:
    FRAME_START + JSON + FRAME_END

New framing:
    FRAME_START + 4-byte big-endian payload length + JSON + FRAME_END

Why this helps
--------------
Single-byte delimiter framing is fragile on noisy links because partial reads
or merged reads can cause false frame boundaries. Length-prefix framing gives
the receiver an exact payload size to expect.
"""

from __future__ import annotations

import base64
import json
import time
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from common.demo_log import (
    dlog,
    banner,
    section,
    kv,
    crypto_verdict,
    ml_verdict,
)
from common.telemetry import Telemetry

import serial

from ccsds.frame import canonical_json_bytes, parse_json_bytes
from crypto.aes_gcm import decrypt
from crypto.key_manager import KeyManager
from crypto.mldsa_signatures import verify, b64d
from groundstation.replay_window import ReplayWindow
from models.runtime_detector import RuntimeDetector
from groundstation.feature_logger import FeatureLogger

detector = RuntimeDetector()
feature_logger = FeatureLogger("groundstation/logs/telemetry_normal.csv")

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
    Hold the pieces of one logical packet while chunks arrive.
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

# Raw serial byte buffer. We keep incomplete data here until a full frame exists.
serial_buffer = bytearray()

banner("AegisLEO Ground Station Secure Receiver")
kv("Serial port", SERIAL_PORT)
kv("Baud rate", BAUD_RATE)
kv("KEM alg", key_manager.algorithm)
print("Press Ctrl+C to stop.", flush=True)

# ---------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------


def pretty_time(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def print_stats() -> None:
    global STATS_LAST_PRINT

    now = time.time()
    if now - STATS_LAST_PRINT < STATS_PRINT_INTERVAL:
        return

    STATS_LAST_PRINT = now

    print(
        "[GROUND][STATS] "
        f"frames={STATS['frames_total']} "
        f"utf8_fail={STATS['frames_utf8_fail']} "
        f"json_fail={STATS['frames_json_fail']} "
        f"bad_len={STATS['frames_bad_length']} "
        f"bad_end={STATS['frames_bad_end_marker']} | "
        f"chunks={STATS['chunks_total']} "
        f"ok={STATS['chunks_accepted']} "
        f"dup={STATS['chunks_duplicate']} "
        f"crc_fail={STATS['chunks_crc_fail']} "
        f"conflict={STATS['chunks_conflict']} | "
        f"reassembled={STATS['reassembly_complete']}"
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

            if len(missing) <= 10:
                print(
                    f"[GROUND][RECOVERY] sid={session_id} mid={message_id} "
                    f"remaining_missing={missing}"
                )
            else:
                print(
                    f"[GROUND][RECOVERY] sid={session_id} mid={message_id} "
                    f"remaining_missing_count={len(missing)}"
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

    required = {"t", "sid", "i", "n", "d", "c"}
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
        print(
            f"[GROUND][CRC] bad chunk sid={session_id} mid={message_id} "
            f"idx={chunk_index} expected={expected_crc:#010x} actual={actual_crc:#010x}"
        )
        return None

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

    if accepted_duplicate:
        STATS["chunks_duplicate"] += 1

    if conflicting_duplicate:
        STATS["chunks_conflict"] += 1
        print(
            f"[GROUND][WARN] conflicting duplicate chunk sid={session_id} "
            f"mid={message_id} idx={chunk_index} -> resetting assembly"
        )
        del reassembly_buffers[key]
        return None

    if not accepted_duplicate:
        STATS["chunks_accepted"] += 1

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

    STATS["reassembly_complete"] += 1

    if DEBUG_REASSEMBLY:
        print(
            f"[GROUND][REASSEMBLED] t={chunk_type} sid={session_id} "
            f"mid={message_id} len={len(assembled_b64)}"
        )

    return session_id, message_id, assembled_b64


def extract_framed_packets(buffer: bytearray) -> list[bytes]:
    
    """
    Extract complete length-prefixed frames from the raw serial buffer.

    Frame format
    ------------
    [FRAME_START][LEN:4][PAYLOAD][FRAME_END]

    Why this parser exists
    ----------------------
    LoRa/serial links can split, merge, or corrupt bytes. We therefore:
    - discard garbage before FRAME_START
    - require the 4-byte payload length field
    - wait until the full frame is present
    - verify FRAME_END before accepting the payload
    - drop 1 byte and resync if framing looks wrong

    Important design rule
    ---------------------
    We trust the payload length more than blind delimiter searching.
    That gives us more stable recovery on noisy links.
    """
    frames: list[bytes] = []

    while True:
        start = buffer.find(FRAME_START)

        if start == -1:
            buffer.clear()
            break

        if start > 0:
            del buffer[:start]

        # Need at least:
        # 1 byte FRAME_START + 4 byte length field
        if len(buffer) < 1 + FRAME_LEN_BYTES:
            break

        if buffer[0:1] != FRAME_START:
            del buffer[0]
            continue

        payload_len = int.from_bytes(buffer[1:5], "big")

        if payload_len <= 0 or payload_len > MAX_FRAME_JSON_BYTES:
            if DEBUG_BAD_FRAMES:
                print(f"[GROUND] WARN: invalid frame length {payload_len}, dropping 1 byte to resync")
            del buffer[0]
            continue

        total_len = 1 + 4 + payload_len + 1  # start + len + payload + end

        if len(buffer) < total_len:
            # Incomplete frame, wait for more bytes.
            break

        payload = bytes(buffer[5:5 + payload_len])
        end_marker = buffer[5 + payload_len:5 + payload_len + 1]

        if end_marker != FRAME_END:
            # Count framing failures so the stats line reflects reality.
            STATS["frames_bad_end_marker"] += 1

            # Only print every 10th framing warning to keep logs readable.
            # We still count every failure in STATS.
            if DEBUG_BAD_FRAMES and STATS["frames_bad_end_marker"] % 10 == 0:
                print(
                    f"[GROUND] WARN: bad frame end marker {end_marker!r}, "
                    f"count={STATS['frames_bad_end_marker']} "
                    "dropping 1 byte to resync"
                )

            # Drop one byte and search for the next valid frame start.
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
        # Bigger read helps reduce application-layer fragmentation.
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
                # Quick sanity check:
                # all transport packets should be JSON objects, so the raw
                # payload should begin with "{". If not, the frame is almost
                # certainly misaligned or corrupted.
                if not frame_bytes.startswith(b"{"):
                    if DEBUG_BAD_FRAMES:
                        print(f"[GROUND] WARN: non-JSON frame dropped: {frame_bytes[:80]!r}")
                    STATS["frames_json_fail"] += 1
                    continue

                text = frame_bytes.decode("utf-8").strip()
                if not text:
                    continue

                transport_packet = json.loads(text)

            except UnicodeDecodeError:
                STATS["frames_utf8_fail"] += 1
                if DEBUG_BAD_FRAMES:
                    print(f"[GROUND] WARN: non-UTF8 frame dropped: {frame_bytes[:80]!r}")
                continue

            except json.JSONDecodeError:
                STATS["frames_json_fail"] += 1
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
                        print("[GROUND] REJECTED: session_init signature invalid")
                        send_nack(session_id=session_id, message_id=message_id, missing=[0])
                        continue

                    session_id = packet["session_id"]

                    if session_id in sessions:
                        print(f"[GROUND] INFO: session already exists ({session_id})")
                        send_ack(session_id, message_id)
                        continue

                    dlog("GROUND", "SESSION_INIT_RX", "Received signed session-init", session=session_id)

                    session = key_manager.create_receiver_session(
                        kem_ciphertext=b64d(packet["kem_ciphertext"]),
                        receiver_private_key=RECEIVER_KEM_PRIVATE_KEY,
                        session_id=session_id,
                    )

                    sessions[session_id] = session
                    replay_windows[session_id] = ReplayWindow(window_size=64)

                    dlog("GROUND", "SESSION_ESTABLISHED", "Receiver session established", session=session_id)
                    send_ack(session_id, message_id)
                    continue

                except Exception as exc:
                    print(f"[GROUND] REJECTED: session_init processing failed: {exc}")
                    send_nack(session_id=session_id, message_id=message_id, missing=[0])
                    continue

            # =========================================================
            # TELEMETRY
            # =========================================================
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
                
                """
                Extract complete length-prefixed frames from the raw serial buffer.

                Frame format
                ------------
                [FRAME_START][LEN:4][PAYLOAD][FRAME_END]

                Why this parser exists
                ----------------------
                LoRa/serial links can split, merge, or corrupt bytes. We therefore:
                - discard garbage before FRAME_START
                - require the 4-byte payload length field
                - wait until the full frame is present
                - verify FRAME_END before accepting the payload
                - drop 1 byte and resync if framing looks wrong

                Important design rule
                ---------------------
                We trust the payload length more than blind delimiter searching.
                That gives us more stable recovery on noisy links.
                """
                if DEBUG_SHOW_CIPHERTEXT:
                    ciphertext_b64 = packet["ciphertext"]
                    nonce_b64 = packet["nonce"]

                    print("-" * 72)
                    print("Encrypted Telemetry View (before decrypt)")
                    print("Algorithms : Session key via ML-KEM-1024 | Payload encrypted with AES-GCM | Packet signed with ML-DSA-65")
                    print(f"Session ID  : {packet['session_id']}")
                    print(f"Nonce       : {nonce_b64}")
                    print(f"Nonce len   : {len(nonce_b64)} base64 chars")
                    print(
                        f"Ciphertext  : {ciphertext_b64[:CIPHERTEXT_PREVIEW_LEN]}"
                        f"{'...' if len(ciphertext_b64) > CIPHERTEXT_PREVIEW_LEN else ''}"
                    )
                    print(f"CT length   : {len(ciphertext_b64)} base64 chars")
                    print("-" * 72)
                    
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

                payload = frame["payload"]

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
                
                feature_logger.log(telemetry.to_feature_dict())

                detection = detector.detect(telemetry)
                

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
                print("Proof      : ciphertext shown above, plaintext shown below after AES-GCM decrypt")

                if detection.is_anomalous:
                    print(
                        f"ML         : ANOMALY "
                        f"(score={detection.score}, reasons={detection.reasons})"
                    )
                else:
                    print(f"ML         : nominal (score={detection.score})")

                print(f"Summary    : {telemetry.summary()}")
                print("=" * 72)

                send_ack(session_id, message_id)















            except Exception as exc:
                print(
                    f"[GROUND] REJECTED: telemetry processing failed "
                    f"sid={session_id} mid={message_id}: {exc}"
                )
                send_nack(session_id=session_id, message_id=message_id, missing=[0])

        print_stats()

    except Exception as exc:
        print(f"[GROUND] WARN: {exc}")