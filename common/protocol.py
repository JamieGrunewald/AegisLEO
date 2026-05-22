"""
AegisLEO — Binary Packet Protocol
===================================

Created by: Jamie Grunewald
Date: 2026-03-08
Version: v0.1.0

Purpose
-------
Defines a simple CCSDS-inspired binary packet format used in early AegisLEO
development. This is NOT a full CCSDS implementation, but provides:
- a structured header (routing, sequence, timestamp)
- a payload (JSON telemetry bytes)
- a CRC32 integrity check

Note: The active transmitter/receiver pipeline (satellite/transmitter.py and
groundstation/receiver.py) uses the JSON-over-LoRa transport in ccsds/frame.py
rather than this binary format. This module is retained as reference and is
used by the test suite (tests/test_packet.py).

Why a custom packet format?
---------------------------
For a realistic demo we want something more "space-ish" than raw JSON, with:
- deterministic parsing (binary header)
- easy logging (apid, seq, timestamp)
- integrity checks (CRC32, later superseded by AES-GCM authentication)

Header layout (network byte order / big-endian)
-----------------------------------------------
SYNC (2 bytes)       : "SL" magic — quickly rejects random bytes
VERSION (1 byte)     : format version
FLAGS (1 byte)       : feature bits (reserved, currently 0)
APID (2 bytes)       : Application Process ID (subsystem identifier)
SEQ (4 bytes)        : packet sequence number
TS_MS (4 bytes)      : timestamp in milliseconds (32-bit truncated)
PAYLOAD_LEN (4 bytes): payload length in bytes
CRC32 (4 bytes)      : CRC of (header-with-crc=0 + payload)

Total header size: 22 bytes.

CRC32 is not a cryptographic primitive — it catches corruption and
accidental tampering. AES-256-GCM (crypto/aes_gcm.py) provides
cryptographic authentication in the live pipeline.
"""
"""

from __future__ import annotations

import json
import struct
import time
import zlib
from dataclasses import dataclass
from typing import Any, Dict, Tuple

# A short "magic" prefix. This is like a file signature.
# It helps the receiver quickly decide "is this one of our packets?"
SYNC = b"SL"

# Increment this if we change header format in a breaking way.
VERSION = 1

# struct format string (big-endian):
# !   = network byte order (big-endian)
# 2s  = 2-byte string
# B   = unsigned char (1 byte)
# H   = unsigned short (2 bytes)
# I   = unsigned int (4 bytes)
_HDR_FMT = "!2sBBHIIII"
_HDR_SIZE = struct.calcsize(_HDR_FMT)


@dataclass(frozen=True)
class Packet:
    """
    Represents one telemetry packet.

    Attributes
    ----------
    apid : int
        Application ID (subsystem identifier).
    seq : int
        Sequence number (increases every packet).
    ts_ms : int
        Timestamp in milliseconds (32-bit truncated).
    flags : int
        Reserved bitfield for features (0 for now).
    payload : bytes
        Payload bytes. For now, JSON-encoded telemetry.
    """

    apid: int
    seq: int
    ts_ms: int
    flags: int
    payload: bytes

    def to_bytes(self) -> bytes:
        """
        Serialize Packet -> bytes, including CRC32.

        Implementation detail:
        - We pack the header with CRC=0 first
        - Compute CRC32 over (header_with_crc_zero + payload)
        - Pack header again with real CRC
        """
        hdr_wo_crc = struct.pack(
            _HDR_FMT,
            SYNC,
            VERSION,
            self.flags & 0xFF,
            self.apid & 0xFFFF,
            self.seq & 0xFFFFFFFF,
            self.ts_ms & 0xFFFFFFFF,
            len(self.payload) & 0xFFFFFFFF,
            0,  # CRC placeholder
        )

        crc = zlib.crc32(hdr_wo_crc + self.payload) & 0xFFFFFFFF

        hdr = struct.pack(
            _HDR_FMT,
            SYNC,
            VERSION,
            self.flags & 0xFF,
            self.apid & 0xFFFF,
            self.seq & 0xFFFFFFFF,
            self.ts_ms & 0xFFFFFFFF,
            len(self.payload) & 0xFFFFFFFF,
            crc,
        )

        return hdr + self.payload

    @staticmethod
    def from_bytes(data: bytes) -> "Packet":
        """
        Parse bytes -> Packet, verifying SYNC, VERSION, payload length, and CRC32.

        Raises
        ------
        ValueError
            If the packet is malformed or CRC does not match.
        """
        if len(data) < _HDR_SIZE:
            raise ValueError(f"packet too short: {len(data)} bytes (need >= {_HDR_SIZE})")

        sync, ver, flags, apid, seq, ts_ms, payload_len, crc = struct.unpack(
            _HDR_FMT, data[:_HDR_SIZE]
        )

        if sync != SYNC:
            raise ValueError(f"bad sync marker: {sync!r}")
        if ver != VERSION:
            raise ValueError(f"unsupported version: {ver}")

        expected_len = _HDR_SIZE + payload_len
        if len(data) != expected_len:
            raise ValueError(f"length mismatch: got {len(data)}, expected {expected_len}")

        payload = data[_HDR_SIZE:]

        # Recompute CRC by packing the same header but forcing CRC field to 0.
        hdr_wo_crc = struct.pack(
            _HDR_FMT,
            SYNC,
            VERSION,
            flags,
            apid,
            seq,
            ts_ms,
            payload_len,
            0,
        )
        calc = zlib.crc32(hdr_wo_crc + payload) & 0xFFFFFFFF

        if calc != crc:
            raise ValueError(f"crc mismatch: got {crc:#x}, calc {calc:#x}")

        return Packet(apid=apid, seq=seq, ts_ms=ts_ms, flags=flags, payload=payload)


def now_ms() -> int:
    """
    Current UNIX time in milliseconds.

    We truncate to 32-bit to keep the header compact (like embedded systems often do).
    """
    return int(time.time() * 1000) & 0xFFFFFFFF


def encode_telemetry_json(obj: Dict[str, Any]) -> bytes:
    """
    Encode a telemetry dict into bytes.

    We use compact JSON to reduce size and keep deterministic ordering.
    """
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def decode_telemetry_json(payload: bytes) -> Dict[str, Any]:
    """Decode telemetry JSON bytes back into a dict."""
    return json.loads(payload.decode("utf-8"))


# --- Optional stream framing helpers ---
# UDP preserves message boundaries, so you do NOT need these for UDP.
# For TCP (a stream), you DO need framing to know where each packet ends.

def frame(packet_bytes: bytes) -> bytes:
    """
    Prepend a 4-byte length prefix so multiple packets can travel over TCP safely.
    """
    return struct.pack("!I", len(packet_bytes)) + packet_bytes


def deframe(buffer: bytes) -> Tuple[bytes, bytes]:
    """
    Extract one length-prefixed packet from a TCP buffer.

    Returns:
        (one_packet_bytes, remainder_bytes)

    Raises:
        ValueError if we don't have enough bytes yet.
    """
    if len(buffer) < 4:
        raise ValueError("incomplete frame header")
    (n,) = struct.unpack("!I", buffer[:4])
    if len(buffer) < 4 + n:
        raise ValueError("incomplete frame body")
    return buffer[4 : 4 + n], buffer[4 + n :]
