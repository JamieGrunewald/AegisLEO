"""
AegisLEO Ground Station Secure Receiver
Transport-Hardened RF Version with ReassemblyFactory + Byte-Stuffed Framing

Created by: Jamie Grunewald
Date: 2026-03-25
Version: v0.13.0

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

Framing in this version
-----------------------
Wire format (both directions):
    FRAME_START + STUFFED_LEN(4+) + PAYLOAD + FRAME_END

The 4-byte big-endian length field is byte-stuffed so that 0x7E, 0x7F,
and 0x7D never appear raw inside it. This prevents the parser from
misreading a length byte as a frame boundary on a noisy RF link.

Reassembly in this version
---------------------------
ChunkAssembly and buffer management have been extracted into
ReassemblyFactory (groundstation/reassembly.py). receiver.py now calls
factory.add_chunk() per incoming chunk and factory.flush_stale() on
idle cycles to send NACKs for expired incomplete messages.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any
from common.demo_log import (
    dlog,
    banner,
    kv,
)
from common.telemetry_model import Telemetry

import serial

from ccsds.frame import canonical_json_bytes, parse_json_bytes
from crypto.aes_gcm import decrypt
from crypto.key_manager import KeyManager
from crypto.mldsa_signatures import verify, b64d
from groundstation.replay_window import ReplayWindow
from models.runtime_detector import RuntimeDetector
from groundstation.feature_logger import FeatureLogger

from groundstation.reassembly import ReassemblyFactory, decode_assembled_payload
factory = ReassemblyFactory()

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

# Byte-stuffing constants.
# The 4-byte length field is escaped so 0x7E/0x7F/0x7D never appear
# raw inside it, preventing false frame-boundary detection on RF links.
FRAME_ESC     = 0x7D   # escape byte
FRAME_ESC_XOR = 0x20   # XOR mask: 0x7E->0x5E, 0x7F->0x5F, 0x7D->0x5D

# Maximum JSON payload size inside one transport frame.
MAX_FRAME_JSON_BYTES = 4096

TELEMETRY_TTL_SECONDS = 30.0
SESSION_INIT_TTL_SECONDS = 120

MAX_MISSING_PER_NACK = 36   

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
NACK_LAST_SENT = time.time()
NACK_SEND_INTERVAL = 30.0

# ---------------------------------------------------------------------
# Load key material
# ---------------------------------------------------------------------
with open(SATELLITE_MLDSA_PUBLIC_KEY_PATH, "rb") as f:
    SATELLITE_MLDSA_PUBLIC_KEY = f.read()

with open(RECEIVER_KEM_PRIVATE_KEY_PATH, "rb") as f:
    RECEIVER_KEM_PRIVATE_KEY = f.read()


# ---------------------------------------------------------------------
# Runtime objects
# ---------------------------------------------------------------------
ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=0.2)

key_manager = KeyManager()
detector = RuntimeDetector()

sessions: dict[str, object] = {}
replay_windows: dict[str, ReplayWindow] = {}


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


def _stuff_length(length_bytes: bytes) -> bytes:
    """
    Byte-stuff a 4-byte length field before writing to the wire.

    Why we need this
    ----------------
    Our frame delimiters are 0x7E (FRAME_START) and 0x7F (FRAME_END).
    If either of those values appears raw inside the 4-byte length field,
    the parser on the other side will misread it as a frame boundary and
    lose alignment. We escape them so the length field is always safe.

    Encoding table:
        0x7E  ->  0x7D 0x5E   (start marker escaped)
        0x7F  ->  0x7D 0x5F   (end marker escaped)
        0x7D  ->  0x7D 0x5D   (escape byte itself escaped)
    """
    out = bytearray()
    for b in length_bytes:
        if b in (0x7E, 0x7F, 0x7D):
            out.append(FRAME_ESC)
            out.append(b ^ FRAME_ESC_XOR)
        else:
            out.append(b)
    return bytes(out)


def _unstuff_length(buf: bytearray, start: int) -> tuple[int | None, int]:
    """
    Read and unstuff a 4-byte length field from the receive buffer.

    Parameters
    ----------
    buf   : the raw serial receive buffer (bytearray)
    start : index in buf where the (possibly stuffed) length field begins
            (immediately after the FRAME_START byte)

    Returns
    -------
    (length_value, bytes_consumed)
        length_value  = the decoded integer length, or None if buf is
                        too short to read the full length field yet
        bytes_consumed = how many raw bytes from buf the length field used
                         (4 minimum, up to 8 in the worst case where all
                          four bytes needed escaping)

    How it works
    ------------
    We read bytes one at a time. If we see the escape byte (0x7D) we
    consume the NEXT byte too and XOR it with 0x20 to recover the
    original value. We keep going until we have decoded 4 bytes of
    actual length data.
    """
    out = bytearray()   # decoded length bytes accumulated here
    i = start           # current position in buf

    while len(out) < 4:
        if i >= len(buf):
            return None, 0      # not enough bytes yet — wait for more

        b = buf[i]

        if b == FRAME_ESC:
            # Escape sequence: the NEXT byte is the real value XOR 0x20
            if i + 1 >= len(buf):
                return None, 0  # escape byte arrived but follower hasn't yet
            out.append(buf[i + 1] ^ FRAME_ESC_XOR)
            i += 2              # consumed 2 raw bytes for 1 decoded byte
        else:
            out.append(b)
            i += 1              # consumed 1 raw byte for 1 decoded byte

    # i - start = total raw bytes consumed by the length field
    return int.from_bytes(out, "big"), i - start


def write_framed_packet(pkt: dict[str, Any]) -> None:
    """
    Send one ACK/NACK control packet back to the satellite using
    the length-prefixed framing format.

    Frame format:
        [FRAME_START][LEN:4][PAYLOAD][FRAME_END]
    """
    payload = json.dumps(pkt, separators=(",", ":")).encode("utf-8")
    # Byte-stuff the length so 0x7E/0x7F/0x7D never appear raw in it.
    length = _stuff_length(len(payload).to_bytes(4, "big"))
    wire = FRAME_START + length + payload + FRAME_END
    ser.write(wire)
    ser.flush()
    # Wait for LoRa half-duplex TX->RX turnaround before sending.
    # Without this, the NACK arrives while the Pi module is still
    # switching modes, causing frame corruption on the receive side.
    time.sleep(1.5)


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

def add_transport_chunk(packet: dict[str, Any]) -> tuple[str, int | None, str] | None:
    """
    Hand one incoming transport chunk to ReassemblyFactory.

    Returns (session_id, message_id, assembled_b64) when ALL chunks for
    this message have arrived and the full payload is ready to decode.
    Returns None while we are still waiting for more chunks.

    Why this wrapper exists
    -----------------------
    The main loop calls this by name for every incoming chunk packet.
    All factory interaction and stats sync lives here in one place,
    keeping the main loop readable.
    """
    chunk_type    = packet["t"]
    session_id    = packet["sid"]
    message_id    = packet.get("mid")
    chunk_index   = int(packet["i"])
    chunk_total   = int(packet["n"])
    data_fragment = packet["d"]
    crc_expected  = int(packet["c"])

    # Hand the chunk to the factory.
    # It handles: CRC check, duplicate detection, conflict detection,
    # TTL cleanup, buffer management, and reassembly completion.
    is_complete, missing = factory.add_chunk(
        chunk_type=chunk_type,
        session_id=session_id,
        message_id=message_id,
        chunk_index=chunk_index,
        chunk_total=chunk_total,
        data_fragment=data_fragment,
        crc_expected=crc_expected,
    )

    # Sync factory stats into the local STATS dict so print_stats() works.
    state = factory.debug_state()
    STATS["chunks_total"]      = state["chunks_total"]
    STATS["chunks_accepted"]   = state["chunks_accepted"]
    STATS["chunks_duplicate"]  = state["chunks_duplicate"]
    STATS["chunks_conflict"]   = state["chunks_conflict"]
    STATS["chunks_crc_fail"]   = state["chunks_crc_fail"]
    STATS["reassembly_complete"] = state["reassembled"]

    if DEBUG_CHUNKS:
        suffix = "" if not missing else f" missing={len(missing)}"
        print(
            f"[GROUND][CHUNK] t={chunk_type} sid={session_id} "
            f"mid={message_id} idx={chunk_index}/{chunk_total - 1}{suffix}"
        )

    if not is_complete:
        return None

    # Message is complete. Retrieve the assembled payload and clean up.
    assembled_b64 = factory.get_assembled(chunk_type, session_id, message_id)
    if assembled_b64 is None:
        return None  # Defensive guard, should not happen in normal flow.

    if DEBUG_REASSEMBLY:
        print(
            f"[GROUND][REASSEMBLED] t={chunk_type} sid={session_id} "
            f"mid={message_id} len={len(assembled_b64)}"
        )

    return session_id, message_id, assembled_b64


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

        # Unstuff the length field. It starts at index 1 (after FRAME_START).
        # _unstuff_length returns (None, 0) if the buffer doesn't yet have
        # enough bytes to decode a full length field — we wait for more.
        payload_len, len_consumed = _unstuff_length(buffer, 1)

        if payload_len is None:
            break   # incomplete length field, wait for more serial data

        if payload_len <= 0 or payload_len > MAX_FRAME_JSON_BYTES:
            if DEBUG_BAD_FRAMES:
                print(f"[GROUND] WARN: invalid frame length {payload_len}, dropping 1 byte to resync")
            STATS["frames_bad_length"] += 1
            del buffer[0]
            continue

        # Total frame size accounts for variable-width stuffed length field:
        #   1 (FRAME_START) + len_consumed (stuffed length) + payload_len + 1 (FRAME_END)
        total_len = 1 + len_consumed + payload_len + 1

        if len(buffer) < total_len:
            # Incomplete frame — wait for more bytes.
            break

        payload_start = 1 + len_consumed
        payload = bytes(buffer[payload_start:payload_start + payload_len])
        end_marker = buffer[total_len - 1:total_len]

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
            # No data arrived this read cycle.
            # Ask the factory to evict any stale incomplete messages
            # and send a NACK for each one so the satellite knows to retry.
            # Periodically send NACKs for incomplete sessions without expiring buffers
            now = time.time()
            if now - NACK_LAST_SENT >= NACK_SEND_INTERVAL:
                NACK_LAST_SENT = now
                for key, buf in list(factory._buffers.items()):
                    if not buf.is_complete():
                        _, session_id_k, message_id_k = key
                        missing_k = buf.missing_indexes()
                        if missing_k:
                            label = "session_init" if message_id_k is None else "telemetry"
                            if DEBUG_ACKS:
                                print(f"[GROUND][INFO] periodic nack {label} sid={session_id_k} mid={message_id_k} missing_count={len(missing_k)}")
                            send_nack(session_id=session_id_k, message_id=message_id_k, missing=missing_k)
            for sid, mid, missing in factory.flush_stale():
                label = "session_init" if mid is None else "telemetry"
                if DEBUG_ACKS:
                    print(f"[GROUND][INFO] stale {label} sid={sid} mid={mid} missing_count={len(missing)}")
                send_nack(session_id=sid, message_id=mid, missing=missing)
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

            # add_transport_chunk hands this chunk to ReassemblyFactory.
            # Returns None while chunks are still missing.
            # Returns (session_id, message_id, assembled_b64) when complete.
            reassembled = add_transport_chunk(transport_packet)
            if reassembled is None:
                continue

            session_id, message_id, assembled_b64 = reassembled

            try:
                # decode_assembled_payload reverses the transmitter pipeline:
                #   base64 -> zlib decompress -> JSON parse -> Python dict
                packet = decode_assembled_payload(assembled_b64)
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