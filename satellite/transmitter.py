"""
AegisLEO Secure Satellite Telemetry Transmitter
Transport-Hardened RF Version with Selective session_init Recovery

Created by: Jamie Grunewald
Date: 2026-03-26
Version: v0.13.0

What changed in v0.13.0
-----------------------
1. Added progress-aware telemetry recovery
2. Increased patience for lossy-link telemetry delivery
3. Reduced premature give-up behavior on late NACK/ACK cycles
4. Kept one telemetry message in flight at a time
5. Byte-stuffed length field in write_transport_packet so 0x7E/0x7F
   never appear raw in the length field and cause framing misalignment
6. Matching byte-unstuffing in extract_framed_packets for ACK/NACK parsing
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

from common.demo_log import dlog, banner, kv
from common.telemetry import sample_telemetry
from ccsds.frame import build_frame, canonical_json_bytes
from crypto.aes_gcm import encrypt
from crypto.key_manager import KeyManager
from crypto.mldsa_signatures import sign, b64e

# ---------------------------------------------------------------------
# Serial / link settings
# ---------------------------------------------------------------------
SERIAL_PORT = "/dev/ttyACM0"
BAUD_RATE = 115200

# ---------------------------------------------------------------------
# Mission / packet identity
# ---------------------------------------------------------------------
SPACECRAFT_ID = "AegisLEO-SAT-1"
APID = 100

# ---------------------------------------------------------------------
# Chunking / pacing
# ---------------------------------------------------------------------
SESSION_INIT_CHUNK_SIZE = 110
TELEMETRY_CHUNK_SIZE = 110

SESSION_INIT_CHUNK_DELAY_SECONDS = 0.50
TELEMETRY_CHUNK_DELAY_SECONDS = 0.35

ACK_WAIT_SECONDS = 50.0

# Session-init and telemetry need different patience profiles.
SESSION_INIT_LISTEN_CYCLES = 32

# Telemetry on this lossy link clearly needs more breathing room.
TELEMETRY_MAX_CYCLES = 14
TELEMETRY_MAX_QUIET_CYCLES = 3

# ---------------------------------------------------------------------
# Framing markers used over the serial link
# ---------------------------------------------------------------------
# Every frame we send over the serial link is wrapped like this:
#
#   [FRAME_START][STUFFED_LENGTH(4+)][PAYLOAD][FRAME_END]
#
# FRAME_START (0x7E) marks where a frame begins.
# FRAME_END   (0x7F) marks where a frame ends.
#
# The receiver scans the raw byte stream for FRAME_START, then reads
# the length field to know exactly how many payload bytes to expect,
# then confirms FRAME_END is in the right place.
FRAME_START = b"\x7E"
FRAME_END = b"\x7F"

# Byte-stuffing constants
# -----------------------
# Problem: our chunk payloads are 140-220 bytes long. The low byte of
# the 4-byte big-endian length field will regularly be 0x7E (126) or
# 0x7F (127) — right in that range. When that happens, the receiver
# finds a false FRAME_START or FRAME_END inside the length field, loses
# byte alignment, and every subsequent frame is corrupted. This was the
# root cause of the bad_end cascade seen in the transmitter logs.
#
# Solution: byte-stuffing (the same technique used in HDLC and PPP).
# Before writing the length field to the wire, we escape any byte that
# could be mistaken for a frame boundary:
#
#   0x7E  ->  0x7D 0x5E    (0x7E XOR 0x20 = 0x5E)
#   0x7F  ->  0x7D 0x5F    (0x7F XOR 0x20 = 0x5F)
#   0x7D  ->  0x7D 0x5D    (0x7D XOR 0x20 = 0x5D, escape byte itself)
#
# The receiver reverses this when reading the length field.
# The payload itself does NOT need stuffing — it is base64 encoded and
# base64 only uses A-Z a-z 0-9 + / = which never contain 0x7E or 0x7F.
FRAME_ESC     = 0x7D   # escape byte — signals that the next byte is stuffed
FRAME_ESC_XOR = 0x20   # XOR mask applied to the original byte after escaping

# ---------------------------------------------------------------------
# Debug flags
# ---------------------------------------------------------------------
DEBUG_TX_CHUNKS = False
DEBUG_ACKS = True
DEBUG_BAD_FRAMES = True
DEBUG_PACKET_SIZES = True

# ---------------------------------------------------------------------
# Compression / crypto config
# ---------------------------------------------------------------------
COMPRESSION_LEVEL = 6
MLDSA_ALGORITHM = "ML-DSA-65"

SATELLITE_MLDSA_SECRET_KEY_PATH = "keys/satellite_mldsa_secret.key"
RECEIVER_KEM_PUBLIC_KEY_PATH = "dev_secrets/satellite/receiver_kem_public.key"


def packet_to_base64_with_stats(packet: dict[str, Any]) -> tuple[str, int, int, int]:
    """
    Convert a packet dict into:
      1. compact JSON bytes
      2. zlib-compressed bytes
      3. base64 text for chunk transport

    Returns:
        (encoded_text, raw_len, compressed_len, encoded_len)
    """
    raw = json.dumps(packet, separators=(",", ":")).encode("utf-8")
    compressed = zlib.compress(raw, level=COMPRESSION_LEVEL)
    encoded = base64.b64encode(compressed).decode("utf-8")
    return encoded, len(raw), len(compressed), len(encoded)


def split_chunks(text: str, chunk_size: int) -> list[str]:
    """Split a long string into fixed-size transport fragments."""
    return [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]


def make_chunk_packets(
    chunk_type: str,
    session_id: str,
    encoded_payload: str,
    chunk_size: int,
    message_id: int | None = None,
) -> list[dict[str, Any]]:
    """
    Wrap a base64 payload into chunk packets for transport.

    Packet fields:
      t   = chunk type ("si" for session init, "tc" for telemetry chunk)
      sid = session id
      i   = chunk index
      n   = total chunk count
      d   = data fragment
      c   = CRC32 of the fragment
      mid = message id (used for telemetry, omitted for session init)
    """
    fragments = split_chunks(encoded_payload, chunk_size)
    total = len(fragments)

    packets: list[dict[str, Any]] = []
    for idx, frag in enumerate(fragments):
        frag_crc = zlib.crc32(frag.encode("utf-8")) & 0xFFFFFFFF

        pkt: dict[str, Any] = {
            "t": chunk_type,
            "sid": session_id,
            "i": idx,
            "n": total,
            "d": frag,
            "c": frag_crc,
        }

        if message_id is not None:
            pkt["mid"] = message_id

        packets.append(pkt)

    return packets


def _stuff_length(length_bytes: bytes) -> bytes:
    """
    Byte-stuff a 4-byte length field before writing it to the wire.

    Why the leading underscore?
    ---------------------------
    In Python, a single leading underscore means "private helper".
    It signals to other developers: this function is an internal detail,
    not part of the public interface. You should call write_transport_packet(),
    not _stuff_length() directly.

    What it does
    ------------
    Walks through the 4 raw length bytes one at a time. Any byte that
    equals 0x7E, 0x7F, or 0x7D gets replaced with a two-byte escape
    sequence. All other bytes pass through unchanged.

    Example
    -------
    Payload length = 126 (0x0000007E in big-endian)
    Raw bytes      = [0x00, 0x00, 0x00, 0x7E]
    After stuffing = [0x00, 0x00, 0x00, 0x7D, 0x5E]  <- 5 bytes, not 4

    The receiver's _unstuff_length() reverses this exactly.

    Parameters
    ----------
    length_bytes : bytes
        The raw 4-byte big-endian representation of the payload length.

    Returns
    -------
    bytes
        The stuffed version — 4 to 8 bytes depending on how many
        bytes needed escaping.
    """
    out = bytearray()
    for b in length_bytes:
        if b in (0x7E, 0x7F, 0x7D):
            # Escape sequence: emit 0x7D followed by (original XOR 0x20)
            out.append(FRAME_ESC)
            out.append(b ^ FRAME_ESC_XOR)
        else:
            # Safe byte — pass through unchanged
            out.append(b)
    return bytes(out)


def _unstuff_length(buf: bytearray, start: int) -> tuple[int | None, int]:
    """
    Read and unstuff a 4-byte length field from the receive buffer.

    This is the exact reverse of _stuff_length().

    When is this called?
    --------------------
    The transmitter calls this when reading ACK/NACK control packets
    coming BACK from the ground station. The ground station also stuffs
    its length fields (in write_framed_packet), so we must unstuff them
    before we can trust the length value.

    How it works
    ------------
    We read raw bytes from buf starting at index `start`, one at a time.
    We accumulate DECODED bytes in `out` until we have 4 of them.

    If we see FRAME_ESC (0x7D), the NEXT byte is the stuffed value.
    We XOR it with FRAME_ESC_XOR (0x20) to recover the original byte,
    and advance by 2 positions in the raw buffer (consumed 2 raw bytes
    but only produced 1 decoded byte).

    If the byte is anything else, it passes through as-is (1 raw byte
    produces 1 decoded byte).

    Parameters
    ----------
    buf   : bytearray
        The raw serial receive buffer.
    start : int
        Index in buf where the stuffed length field begins.
        This is always 1 (immediately after the FRAME_START byte).

    Returns
    -------
    tuple[int | None, int]
        (length_value, bytes_consumed)

        length_value  : the decoded integer payload length, or None if
                        buf doesn't have enough bytes yet to finish
                        reading the length field — caller should wait
                        for more serial data before trying again.

        bytes_consumed: how many raw bytes from buf the length field
                        used up. Because of stuffing this is between
                        4 (no bytes needed escaping) and 8 (all four
                        bytes needed escaping). The caller uses this
                        to know where the payload actually starts.
    """
    out = bytearray()   # decoded length bytes — we need exactly 4
    i = start           # current read position in the raw buffer

    while len(out) < 4:
        if i >= len(buf):
            # Ran off the end of the buffer before collecting 4 bytes.
            # Tell the caller to wait for more incoming serial data.
            return None, 0

        b = buf[i]

        if b == FRAME_ESC:
            # Escape sequence — the NEXT byte holds the real value XOR 0x20
            if i + 1 >= len(buf):
                # The escape byte arrived but its follower hasn't yet.
                return None, 0
            out.append(buf[i + 1] ^ FRAME_ESC_XOR)
            i += 2      # consumed 2 raw bytes, produced 1 decoded byte
        else:
            out.append(b)
            i += 1      # consumed 1 raw byte, produced 1 decoded byte

    # i - start = total raw bytes consumed by this length field
    return int.from_bytes(out, "big"), i - start


def write_transport_packet(ser: serial.Serial, pkt: dict[str, Any]) -> None:
    """
    Serialize and send one transport chunk packet over the serial link.

    Wire format
    -----------
    [FRAME_START][STUFFED_LEN(4+)][PAYLOAD][FRAME_END]

    FRAME_START   : 1 byte  (0x7E) — marks the start of a frame
    STUFFED_LEN   : 4-8 bytes — big-endian payload length, byte-stuffed
                    so 0x7E/0x7F/0x7D never appear raw and can't be
                    mistaken for frame boundaries
    PAYLOAD       : variable — compact JSON, safe because base64 encoded
    FRAME_END     : 1 byte  (0x7F) — marks the end of a frame

    Parameters
    ----------
    ser : serial.Serial
        The open serial port connected to the LoRa module.
    pkt : dict
        The transport chunk packet to send. Contains fields like
        t, sid, i, n, d, c, and optionally mid.
    """
    # Compact JSON — no extra spaces, smallest possible wire footprint.
    payload = json.dumps(pkt, separators=(",", ":")).encode("utf-8")

    # Byte-stuff the length field so frame boundaries can never appear
    # inside it, regardless of what the payload length value happens to be.
    length = _stuff_length(len(payload).to_bytes(4, "big"))

    wire = FRAME_START + length + payload + FRAME_END
    ser.write(wire)
    ser.flush()

    # Tiny pause to prevent back-to-back writes from overflowing the
    # SX1262 module's serial input buffer on the LoRa side.
    time.sleep(0.02)


def send_chunk_packets(
    ser: serial.Serial,
    packets: list[dict[str, Any]],
    delay_seconds: float,
) -> None:
    """
    Send transport chunks one at a time with pacing.

    Why pacing matters:
    - LoRa is slow and half-duplex
    - The receiver needs breathing room for chunk reassembly
    - Overdriving the line causes retries, NACK storms, and sadness
    """
    total = len(packets)

    for idx, pkt in enumerate(packets):
        write_transport_packet(ser, pkt)

        if DEBUG_TX_CHUNKS:
            dlog(
                "SAT",
                "CHUNK_TX",
                "Transport chunk sent",
                t=pkt["t"],
                sid=pkt["sid"],
                mid=pkt.get("mid"),
                idx=f"{idx + 1}/{total}",
            )

        if pkt["t"] == "tc":
            # Pacing tuned to LoRa SF7/BW125 airtime (~276ms per chunk).
            # delay_seconds = 0.35 gives airtime + 50ms margin.
            # Small jitter prevents lock-step RF collisions.
            time.sleep(delay_seconds + random.uniform(0.01, 0.03))
        else:
            time.sleep(delay_seconds + random.uniform(0.005, 0.02))


def extract_framed_packets(buffer: bytearray) -> list[bytes]:
    """
    Extract complete framed packets from the raw serial receive buffer.

    This is used on the TRANSMITTER side to parse ACK/NACK control
    packets coming BACK from the ground station after each transmission.

    Wire format expected
    --------------------
    [FRAME_START][STUFFED_LEN(4+)][PAYLOAD][FRAME_END]

    Why a buffer instead of just reading bytes directly?
    ----------------------------------------------------
    Serial reads are not guaranteed to give you exactly one frame at a
    time. A single ser.read() call might return:
      - half a frame (the rest hasn't arrived yet)
      - one full frame
      - one and a half frames (next frame started arriving)
      - multiple frames merged together

    So we accumulate ALL incoming bytes into a bytearray buffer and
    then call this function to carve out complete frames. Anything
    incomplete stays in the buffer and gets processed on the next read.

    Recovery behavior
    -----------------
    If the parser finds something that doesn't look right (invalid
    length, wrong end marker), it drops ONE byte and tries again from
    the next position. This means a single corrupted byte causes at most
    one frame to be lost — not a full buffer wipe.
    """
    frames: list[bytes] = []

    while True:
        # Scan forward to the next FRAME_START byte.
        # Anything before it is garbage (partial frame, line noise) — discard.
        start = buffer.find(FRAME_START)

        if start == -1:
            # No frame start anywhere in the buffer — clear everything.
            buffer.clear()
            break

        if start > 0:
            # Junk bytes before the frame start — skip past them.
            del buffer[:start]

        # Need at least FRAME_START + 1 byte of length field to proceed.
        if len(buffer) < 2:
            break

        if buffer[0:1] != FRAME_START:
            del buffer[0]
            continue

        # Decode the stuffed length field starting at index 1.
        # Returns (None, 0) if the buffer is too short to read it fully.
        payload_len, len_consumed = _unstuff_length(buffer, 1)

        if payload_len is None:
            # Haven't received all the length bytes yet — wait for more.
            break

        if payload_len <= 0 or payload_len > 4096:
            # Length value is out of range — this is not a valid frame.
            # Drop one byte and search for the next FRAME_START.
            if DEBUG_BAD_FRAMES:
                dlog("SAT", "WARN", "Invalid frame length while resyncing", payload_len=payload_len)
            del buffer[0]
            continue

        # Total frame size:
        #   1 byte  FRAME_START
        #   len_consumed bytes  stuffed length field (4 to 8 bytes)
        #   payload_len bytes   payload
        #   1 byte  FRAME_END
        total_len = 1 + len_consumed + payload_len + 1

        if len(buffer) < total_len:
            # Full frame hasn't arrived yet — wait for more serial data.
            break

        # Extract the payload bytes from the correct position.
        payload_start = 1 + len_consumed
        payload = bytes(buffer[payload_start:payload_start + payload_len])

        # Verify FRAME_END is exactly where we expect it.
        end_marker = buffer[total_len - 1:total_len]

        if end_marker != FRAME_END:
            # End marker is wrong — alignment is off. Drop one byte and retry.
            if DEBUG_BAD_FRAMES:
                dlog("SAT", "WARN", "Bad frame end marker while resyncing", end_marker=repr(end_marker))
            del buffer[0]
            continue

        # Valid frame — consume it from the buffer and add to results.
        del buffer[:total_len]
        frames.append(payload)

    return frames


def read_control_packet(ser: serial.Serial, timeout_seconds: float) -> dict[str, Any] | None:
    """
    Read one ACK/NACK control packet using framed serial input.
    """
    end_time = time.time() + timeout_seconds
    rx_buffer = bytearray()

    while time.time() < end_time:
        ready, _, _ = select.select([ser.fileno()], [], [], 0.2)
        if not ready:
            continue

        raw = ser.read(512)
        if not raw:
            continue

        rx_buffer.extend(raw)
        frames = extract_framed_packets(rx_buffer)

        for frame_bytes in frames:
            try:
                text = frame_bytes.decode("utf-8").strip()
                if not text:
                    continue
                pkt = json.loads(text)
            except UnicodeDecodeError:
                if DEBUG_BAD_FRAMES:
                    dlog("SAT", "WARN", "Dropped non-UTF8 control frame", preview=repr(frame_bytes[:80]))
                continue
            except json.JSONDecodeError:
                if DEBUG_BAD_FRAMES:
                    dlog("SAT", "WARN", "Dropped invalid JSON control frame", preview=repr(frame_bytes[:80]))
                continue

            if pkt.get("t") in {"ack", "nack"}:
                return pkt

    return None


def resend_missing_chunks(
    ser: serial.Serial,
    pending_chunks: list[dict[str, Any]],
    missing: list[int],
    delay_seconds: float,
) -> None:
    """
    Resend only the missing chunks if the receiver told us which ones it lacks.
    If the missing list is empty or unusable, resend the full set.
    """
    resend = [pkt for pkt in pending_chunks if pkt["i"] in missing]
    if not resend:
        resend = pending_chunks

    send_chunk_packets(ser, resend, delay_seconds)


def control_matches_session(control: dict[str, Any], session_id: str, message_id: int | None) -> bool:
    """
    Validate that a returned ACK/NACK belongs to this session and message.
    """
    if control.get("sid") != session_id:
        return False

    control_mid = control.get("mid")
    if message_id is None:
        return control_mid is None

    return control_mid == message_id


def wait_for_session_init_ack_or_nack(
    ser: serial.Serial,
    session_id: str,
    pending_chunks: list[dict[str, Any]],
    resend_delay_seconds: float,
) -> bool:
    """
    Wait for session-init ACK/NACK and selectively recover missing chunks.
    """
    seen_nack = False

    for cycle in range(1, SESSION_INIT_LISTEN_CYCLES + 1):
        control = read_control_packet(ser, ACK_WAIT_SECONDS)

        if control is not None and DEBUG_ACKS:
            dlog("SAT", "CTRL_RX", "Received control packet", pkt=control)

        if control is None:
            dlog(
                "SAT",
                "ACK_WAIT",
                "Session-init quiet timeout",
                sid=session_id,
                cycle=f"{cycle}/{SESSION_INIT_LISTEN_CYCLES}",
            )

            # Rare nudge resends before the first valid NACK.
            if not seen_nack and cycle in {6, 10}:
                dlog("SAT", "RECOVERY", "Pre-NACK resend-all burst", sid=session_id)
                time.sleep(2.5)
                send_chunk_packets(ser, pending_chunks, resend_delay_seconds)
                time.sleep(2.5)

            continue

        if not control_matches_session(control, session_id, None):
            if DEBUG_ACKS:
                dlog(
                    "SAT",
                    "CTRL_IGNORE",
                    "Ignoring control for different session/message",
                    sid=control.get("sid"),
                    mid=control.get("mid"),
                )
            continue

        control_type = control.get("t")

        if control_type == "ack":
            dlog("SAT", "ACK", "Session-init acknowledged", sid=session_id)
            return True

        if control_type == "nack":
            missing = control.get("m", [])
            dlog(
                "SAT",
                "NACK",
                "Session-init missing chunks reported",
                sid=session_id,
                missing=missing,
                cycle=f"{cycle}/{SESSION_INIT_LISTEN_CYCLES}",
            )

            seen_nack = True
            time.sleep(0.5)
            resend_missing_chunks(
                ser=ser,
                pending_chunks=pending_chunks,
                missing=missing,
                delay_seconds=resend_delay_seconds,
            )
            time.sleep(4.0)

    return False


def wait_for_telemetry_ack_or_nack(
    ser: serial.Serial,
    session_id: str,
    message_id: int,
    pending_chunks: list[dict[str, Any]],
    resend_delay_seconds: float,
) -> bool:
    """
    Progress-aware telemetry recovery loop.

    Key idea:
    - If the receiver's missing set keeps shrinking, recovery is working.
    - Do not abandon the message too early just because the link is slow.
    - Only one telemetry message is in flight at a time.
    """
    quiet_cycles = 0
    last_missing_set: set[int] | None = None

    for cycle in range(1, TELEMETRY_MAX_CYCLES + 1):
        control = read_control_packet(ser, ACK_WAIT_SECONDS)

        if control is not None and DEBUG_ACKS:
            dlog("SAT", "CTRL_RX", "Received control packet", pkt=control)

        if control is None:
            quiet_cycles += 1

            dlog(
                "SAT",
                "ACK_WAIT",
                "Telemetry quiet timeout",
                sid=session_id,
                mid=message_id,
                cycle=f"{cycle}/{TELEMETRY_MAX_CYCLES}",
                quiet=quiet_cycles,
            )

            # Do not immediately blast the full packet again on first silence.
            # Give the receiver a little room to issue a targeted NACK.
            if quiet_cycles >= TELEMETRY_MAX_QUIET_CYCLES:
                dlog(
                    "SAT",
                    "RECOVERY",
                    "Repeated quiet timeout, resending full telemetry packet",
                    sid=session_id,
                    mid=message_id,
                )
                send_chunk_packets(ser, pending_chunks, resend_delay_seconds)
                quiet_cycles = 0
                time.sleep(1.0)

            continue

        if not control_matches_session(control, session_id, message_id):
            if DEBUG_ACKS:
                dlog(
                    "SAT",
                    "CTRL_IGNORE",
                    "Ignoring control for different session/message",
                    sid=control.get("sid"),
                    mid=control.get("mid"),
                )
            continue

        quiet_cycles = 0
        control_type = control.get("t")

        if control_type == "ack":
            dlog("SAT", "ACK", "Telemetry acknowledged", sid=session_id, mid=message_id)
            return True

        if control_type != "nack":
            continue

        missing = control.get("m", [])
        missing_set = set(int(x) for x in missing)

        dlog(
            "SAT",
            "NACK",
            "Telemetry missing chunks reported",
            sid=session_id,
            mid=message_id,
            missing=missing,
            cycle=f"{cycle}/{TELEMETRY_MAX_CYCLES}",
        )

        # Track whether the receiver is making progress.
        if last_missing_set is None:
            dlog(
                "SAT",
                "RECOVERY",
                "Initial telemetry recovery map received",
                sid=session_id,
                mid=message_id,
                missing_count=len(missing_set),
            )
        else:
            improvement = len(last_missing_set) - len(missing_set)
            dlog(
                "SAT",
                "RECOVERY",
                "Telemetry recovery progress",
                sid=session_id,
                mid=message_id,
                previous_missing=len(last_missing_set),
                current_missing=len(missing_set),
                improvement=improvement,
            )

        last_missing_set = missing_set

        time.sleep(0.5)
        resend_missing_chunks(
            ser=ser,
            pending_chunks=pending_chunks,
            missing=missing,
            delay_seconds=resend_delay_seconds,
        )

        # Slightly longer wait after resend gives the receiver time
        # to ingest the correction burst and answer cleanly.
        time.sleep(1.5)

    return False


# ---------------------------------------------------------------------
# Load long-term keys and initialize secure session
# ---------------------------------------------------------------------
with open(SATELLITE_MLDSA_SECRET_KEY_PATH, "rb") as f:
    MLDSA_SECRET_KEY = f.read()

with open(RECEIVER_KEM_PUBLIC_KEY_PATH, "rb") as f:
    RECEIVER_KEM_PUBLIC_KEY = f.read()

key_manager = KeyManager()
initiator_handshake = key_manager.create_initiator_session(RECEIVER_KEM_PUBLIC_KEY)
session = initiator_handshake.session
kem_ciphertext = initiator_handshake.kem_ciphertext

# ---------------------------------------------------------------------
# Open serial transport
# ---------------------------------------------------------------------
ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=0.2)
sequence = 1

banner("AegisLEO Secure Satellite Telemetry Transmitter")
kv("Serial port", SERIAL_PORT)
kv("Baud rate", BAUD_RATE)
kv("Spacecraft", SPACECRAFT_ID)
kv("Session ID", session.session_id)
kv("KEM alg", key_manager.algorithm)
print("Press Ctrl+C to stop.", flush=True)

# ---------------------------------------------------------------------
# Build and send signed session-init packet
# ---------------------------------------------------------------------
session_init_core = {
    "type": "session_init",
    "spacecraft_id": SPACECRAFT_ID,
    "session_id": session.session_id,
    "kem_ciphertext": b64e(kem_ciphertext),
}

session_init_signature = sign(
    canonical_json_bytes(session_init_core),
    MLDSA_SECRET_KEY,
    algorithm=MLDSA_ALGORITHM,
)

session_init_packet = {
    **session_init_core,
    "signature": b64e(session_init_signature),
}

(
    session_init_b64,
    session_init_raw_len,
    session_init_comp_len,
    session_init_enc_len,
) = packet_to_base64_with_stats(session_init_packet)

session_init_chunks = make_chunk_packets(
    chunk_type="si",
    session_id=session.session_id,
    encoded_payload=session_init_b64,
    chunk_size=SESSION_INIT_CHUNK_SIZE,
    message_id=None,
)

if DEBUG_PACKET_SIZES:
    dlog(
        "SAT",
        "SESSION_INIT_PREP",
        "Prepared secure session-init packet",
        raw=session_init_raw_len,
        compressed=session_init_comp_len,
        encoded=session_init_enc_len,
        chunks=len(session_init_chunks),
        chunk_size=SESSION_INIT_CHUNK_SIZE,
    )

send_chunk_packets(ser, session_init_chunks, SESSION_INIT_CHUNK_DELAY_SECONDS)

dlog(
    "SAT",
    "SESSION_INIT_TX",
    "Sent session-init to ground station",
    session=session.session_id,
    chunks=len(session_init_chunks),
)

# Give the half-duplex link time to flip from TX to RX cleanly.
time.sleep(2.5)

session_init_ok = wait_for_session_init_ack_or_nack(
    ser=ser,
    session_id=session.session_id,
    pending_chunks=session_init_chunks,
    resend_delay_seconds=SESSION_INIT_CHUNK_DELAY_SECONDS,
)

if not session_init_ok:
    dlog("SAT", "FATAL", "Session-init delivery failed after retries", session=session.session_id)
    raise SystemExit(1)

dlog("SAT", "SESSION_READY", "Session-init acknowledged by ground station", session=session.session_id)
time.sleep(1)

# ---------------------------------------------------------------------
# Main telemetry transmit loop
# ---------------------------------------------------------------------
while True:
    # Build one human-readable telemetry object for the demo and for the packet.
    telemetry = sample_telemetry(sequence)

    payload = {
        "temp_c": telemetry.temperature_c,
        "bus_v": telemetry.bus_v,
        "bus_i": telemetry.bus_i,
        "state": telemetry.mode,
        "battery_pct": telemetry.battery_pct,
        "latitude": telemetry.latitude,
        "longitude": telemetry.longitude,
        "altitude_km": telemetry.altitude_km,
    }

    dlog(
        "SAT",
        "TELEMETRY_BUILD",
        "Generated telemetry sample",
        seq=telemetry.seq,
        summary=telemetry.summary(),
    )

    # Build CCSDS-style application frame before encryption.
    frame = build_frame(
        spacecraft_id=SPACECRAFT_ID,
        sequence=sequence,
        apid=APID,
        payload=payload,
    )

    frame_bytes = canonical_json_bytes(frame)

    # Encrypt the frame payload using the active session AES key.
    encrypted = encrypt(
        frame_bytes,
        session.aes_key,
        aad=SPACECRAFT_ID.encode("utf-8"),
    )

    # Sign the packet core so the receiver can validate authenticity
    # before attempting decryption.
    packet_core = {
        "type": "telemetry",
        "spacecraft_id": SPACECRAFT_ID,
        "session_id": session.session_id,
        "nonce": b64e(encrypted["nonce"]),
        "ciphertext": b64e(encrypted["ciphertext"]),
    }

    telemetry_signature = sign(
        canonical_json_bytes(packet_core),
        MLDSA_SECRET_KEY,
        algorithm=MLDSA_ALGORITHM,
    )

    transmitted_packet = {
        **packet_core,
        "signature": b64e(telemetry_signature),
    }

    telemetry_b64, telemetry_raw_len, telemetry_comp_len, telemetry_enc_len = (
        packet_to_base64_with_stats(transmitted_packet)
    )

    telemetry_chunks = make_chunk_packets(
        chunk_type="tc",
        session_id=session.session_id,
        encoded_payload=telemetry_b64,
        chunk_size=TELEMETRY_CHUNK_SIZE,
        message_id=sequence,
    )

    # Only one telemetry message is in flight at a time.
    send_chunk_packets(ser, telemetry_chunks, TELEMETRY_CHUNK_DELAY_SECONDS)

    if DEBUG_PACKET_SIZES:
        dlog(
            "SAT",
            "TELEMETRY_TX",
            "Sent secure telemetry packet",
            session=session.session_id,
            seq=sequence,
            chunks=len(telemetry_chunks),
            raw=telemetry_raw_len,
            compressed=telemetry_comp_len,
            encoded=telemetry_enc_len,
            chunk_size=TELEMETRY_CHUNK_SIZE,
        )

    time.sleep(1.0)

    delivery_ok = wait_for_telemetry_ack_or_nack(
        ser=ser,
        session_id=session.session_id,
        message_id=sequence,
        pending_chunks=telemetry_chunks,
        resend_delay_seconds=TELEMETRY_CHUNK_DELAY_SECONDS,
    )

    if not delivery_ok:
        dlog(
            "SAT",
            "DELIVERY_FAIL",
            "Telemetry delivery failed after recovery window",
            seq=sequence,
        )
    else:
        dlog("SAT", "DELIVERY_OK", "Telemetry acknowledged by ground station", seq=sequence)

    sequence += 1
    time.sleep(3)