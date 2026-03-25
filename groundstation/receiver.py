"""
AegisLEO Ground Station Secure Receiver
Transport-Hardened RF Version with Selective Recovery for session_init

Created by: Jamie Grunewald
Updated by: OpenAI ChatGPT
Date: 2026-03-25
Version: v0.11.2

What this script does
---------------------
This script runs on the ground station and listens for secure telemetry
coming from the satellite node over the LoRa serial link.

High-level flow
---------------
1. Read small framed transport packets from serial
2. Validate packet structure
3. Validate chunk CRC so corrupted chunks do not poison reassembly
4. Reassemble chunks into one full logical packet
5. Decode + verify signature + establish/decrypt session data
6. Apply replay protection
7. Run ML anomaly detection
8. Send ACK/NACK back to the satellite side

New in this version
-------------------
1. Transport counters added
2. Periodic stats summary added
3. Noob-level comments restored
4. Slightly larger serial reads
5. Slightly larger max frame size
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

# The USB serial device for the LoRa radio on the ground station.
SERIAL_PORT = "/dev/serial/by-id/usb-1a86_USB_Single_Serial_5AAF186928-if00"

# Serial speed between Python and the LoRa radio bridge.
BAUD_RATE = 115200

# Post-quantum signature algorithm used by the satellite.
MLDSA_ALGORITHM = "ML-DSA-65"

# Public key used to verify packets signed by the satellite.
SATELLITE_MLDSA_PUBLIC_KEY_PATH = "keys/satellite_mldsa_public.key"

# Private ML-KEM key for the ground station so it can decapsulate the session.
RECEIVER_KEM_PRIVATE_KEY_PATH = "dev_secrets/groundstation/receiver_kem_private.key"

# Simple frame markers around each transport JSON packet.
# These help us separate one transport packet from the next.
FRAME_START = b"\x7E"
FRAME_END = b"\x7F"

# Maximum size of one framed transport JSON packet.
# This is a safety guard so random garbage does not grow forever in memory.
MAX_FRAME_JSON_BYTES = 4096

# How long to keep incomplete chunk reassembly state alive.
# session_init gets longer because PQ material is large.
TELEMETRY_TTL_SECONDS = 8.0
SESSION_INIT_TTL_SECONDS = 60.0

# Keep NACK messages compact so the control path stays small.
MAX_MISSING_PER_NACK = 24

# Debug toggles
DEBUG_CHUNKS = True
DEBUG_REASSEMBLY = True
DEBUG_ACKS = True
DEBUG_BAD_FRAMES = True
DEBUG_SCHEMA = True

# ---------------------------------------------------------------------
# Transport / Link Counters
# ---------------------------------------------------------------------
# These counters help us see whether the link is improving or getting worse.
# Instead of guessing, we can compare runs using hard numbers.
STATS = {
    "frames_total": 0,
    "frames_utf8_fail": 0,
    "frames_json_fail": 0,
    "chunks_total": 0,
    "chunks_crc_fail": 0,
    "chunks_duplicate": 0,
    "chunks_conflict": 0,
    "chunks_accepted": 0,
    "reassembly_complete": 0,
}

STATS_LAST_PRINT = time.time()
STATS_PRINT_INTERVAL = 5.0  # seconds

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

    total_chunks
        How many chunks are expected for this one logical packet.

    parts
        Dictionary of:
            chunk_index -> chunk data fragment

    created_at / updated_at
        Used for stale-buffer cleanup.
    """

    total_chunks: int
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    parts: dict[int, str] = field(default_factory=dict)

    def add_part(self, idx: int, data: str) -> tuple[bool, bool]:
        """
        Add one chunk into the assembly.

        Returns
        -------
        (accepted_duplicate, conflicting_duplicate)

        accepted_duplicate = True
            We already had this chunk, and the data matched exactly.

        conflicting_duplicate = True
            We already had this chunk index, but the data was different.
            That usually means corruption, so we should reset that assembly.
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
        """Return True only when all expected chunk indexes are present."""
        return len(self.parts) == self.total_chunks

    def missing_indexes(self) -> list[int]:
        """Return the missing chunk indexes in sorted order."""
        return [i for i in range(self.total_chunks) if i not in self.parts]

    def assemble(self) -> str:
        """
        Rebuild the original encoded payload in chunk order.

        Important:
        We do NOT trust arrival order.
        We reconstruct using chunk index order.
        """
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

# session_id -> SessionState
sessions: dict[str, object] = {}

# session_id -> ReplayWindow
replay_windows: dict[str, ReplayWindow] = {}

# (chunk_type, session_id, message_id) -> ChunkAssembly
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
    """Convert UNIX timestamp to a readable UTC string."""
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def print_stats() -> None:
    """
    Periodically print a compact stats line.

    Why this exists
    ---------------
    On noisy RF links, counters are more useful than raw scrollback.
    This lets us see whether corruption, duplicates, or reassembly success
    are trending in the right direction.
    """
    global STATS_LAST_PRINT

    now = time.time()
    if now - STATS_LAST_PRINT < STATS_PRINT_INTERVAL:
        return

    STATS_LAST_PRINT = now

    print(
        "[GROUND][STATS] "
        f"frames={STATS['frames_total']} "
        f"utf8_fail={STATS['frames_utf8_fail']} "
        f"json_fail={STATS['frames_json_fail']} | "
        f"chunks={STATS['chunks_total']} "
        f"ok={STATS['chunks_accepted']} "
        f"dup={STATS['chunks_duplicate']} "
        f"crc_fail={STATS['chunks_crc_fail']} "
        f"conflict={STATS['chunks_conflict']} | "
        f"reassembled={STATS['reassembly_complete']}"
    )


def write_framed_packet(pkt: dict[str, Any]) -> None:
    """
    Send one small ACK/NACK control packet back to the satellite.

    Tiny pause note
    ---------------
    The pause after flush is intentional.
    Shared half-duplex links often behave better when we do not hammer
    the reverse path immediately after writing.
    """
    payload = json.dumps(pkt, separators=(",", ":")).encode("utf-8")
    wire = FRAME_START + payload + FRAME_END
    ser.write(wire)
    ser.flush()
    time.sleep(0.05)


def send_ack(session_id: str, message_id: int | None) -> None:
    """
    Tell the transmitter:
    'I fully processed this logical packet successfully.'
    """
    pkt: dict[str, Any] = {"t": "ack", "sid": session_id}
    if message_id is not None:
        pkt["mid"] = message_id

    write_framed_packet(pkt)

    if DEBUG_ACKS:
        print(f"[GROUND][ACK] sid={session_id} mid={message_id}")


def send_nack(session_id: str, missing: list[int], message_id: int | None = None) -> None:
    """
    Tell the transmitter:
    'I am missing these chunk indexes.'

    For session_init, mid is None.
    For telemetry, mid is the telemetry sequence number.
    """
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
    """
    session_init gets a longer stale timeout because it carries
    large post-quantum setup material.
    """
    return SESSION_INIT_TTL_SECONDS if message_id is None else TELEMETRY_TTL_SECONDS


def cleanup_reassembly_buffers() -> None:
    """
    Scan incomplete reassemblies and NACK missing chunk indexes
    when a buffer goes stale.

    Important:
    We keep already-received chunks and refresh the timer.
    That way we do not throw away partial progress.
    """
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

        # Keep partial progress, but refresh the timer.
        new_buf = ChunkAssembly(total_chunks=buf.total_chunks)
        new_buf.parts = dict(buf.parts)
        new_buf.updated_at = time.time()
        reassembly_buffers[key] = new_buf


def validate_transport_packet(packet: dict[str, Any]) -> bool:
    """
    Validate the small transport packet that rides directly over RF.

    Expected fields for chunk packets
    ---------------------------------
    t   -> chunk type ("si" or "tc")
    sid -> session id
    i   -> chunk index
    n   -> total chunk count
    d   -> chunk data
    c   -> CRC32 of d

    ACK/NACK control packets are allowed through separately.
    """
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
    """
    Add one validated transport chunk to the reassembly store.

    Returns
    -------
    (session_id, message_id, assembled_b64) when complete
    None otherwise
    """
    cleanup_reassembly_buffers()

    chunk_type = packet["t"]
    session_id = packet["sid"]
    message_id = packet.get("mid")
    chunk_index = int(packet["i"])
    chunk_total = int(packet["n"])
    data_fragment = packet["d"]

    STATS["chunks_total"] += 1

    # -------------------------------------------------------------
    # CRC check
    # -------------------------------------------------------------
    # This catches chunk corruption BEFORE bad data pollutes the
    # reassembly buffer.
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

    # If one logical packet suddenly claims a different total chunk count,
    # that is suspicious. Reset that assembly.
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

    # If we got here, this was a clean accepted chunk.
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
    Pull as many complete framed packets as possible out of the raw byte buffer.

    Framing format
    --------------
    FRAME_START + JSON_BYTES + FRAME_END

    Design note
    -----------
    We drop garbage before FRAME_START.
    We keep partial trailing frames for later.
    We reject giant frames so the parser does not get stuck.
    """
    frames: list[bytes] = []

    while True:
        start = buffer.find(FRAME_START)
        if start == -1:
            # No frame start at all -> drop garbage and stop.
            buffer.clear()
            break

        # Remove garbage before the frame start marker.
        if start > 0:
            del buffer[:start]

        end = buffer.find(FRAME_END, 1)
        if end == -1:
            # Frame not complete yet.
            # If buffer is absurdly large, drop one byte and try to resync.
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


# ---------------------------------------------------------------------
# Main receive loop
# ---------------------------------------------------------------------
while True:
    try:
        # Read a larger chunk from serial each cycle.
        # This may help on noisy links where packets arrive in clumps.
        incoming = ser.read(512)

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

            # Ignore control packets if they somehow loop back onto RX.
            if transport_packet.get("t") in {"ack", "nack"}:
                continue

            # ---------------------------------------------------------
            # Step 1: Reassemble transport chunks
            # ---------------------------------------------------------
            reassembled = add_transport_chunk(transport_packet)
            if reassembled is None:
                continue

            session_id, message_id, assembled_b64 = reassembled

            # ---------------------------------------------------------
            # Step 2: Decode logical packet
            # ---------------------------------------------------------
            try:
                packet = b64text_to_packet(assembled_b64)
            except Exception as exc:
                print(
                    f"[GROUND] WARN: logical packet decode failed "
                    f"sid={session_id} mid={message_id}: {exc}"
                )

                # This is a blunt recovery nudge.
                # We do not truly know which chunks were bad at this stage,
                # but forcing retransmission is better than going silent.
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

            # =========================================================
            # TELEMETRY
            # =========================================================
            if packet_type != "telemetry":
                print(f"[GROUND] WARN: unknown logical packet type: {packet_type}")
                send_nack(session_id=session_id, message_id=message_id, missing=[0])
                continue

            try:
                # Verify the signed outer telemetry packet before decrypting.
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

                # Decrypt the inner CCSDS-style telemetry payload.
                plaintext = decrypt(
                    b64d(packet["nonce"]),
                    b64d(packet["ciphertext"]),
                    session.aes_key,
                    aad=packet["spacecraft_id"].encode("utf-8"),
                )

                # Parse the decrypted telemetry frame.
                frame = parse_json_bytes(plaintext)

                # Replay protection check.
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

                # Run anomaly detection on the parsed telemetry frame.
                detection = detector.detect(frame)

                # Pretty operator output.
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

                # Only ACK after the full logical packet has succeeded end-to-end.
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