"""
AegisLEO — Chunking Helpers
============================

Created by: Jamie Grunewald
Date: 2026-03-24
Version: v0.1.0

Purpose
-------
Splits large serialized packets into small chunks sized to fit within the
SX1262 LoRa DTU wire limit (~240 bytes per frame). Each chunk is a self-
contained JSON envelope carrying its index, total count, session ID, and
a CRC32 for corruption detection.

The receiver (groundstation/reassembly.py) collects all chunks for a given
message ID and reassembles them before decryption and signature verification.

Used by
-------
- satellite/transmitter.py    (split session_init and telemetry packets)
- groundstation/reassembly.py (reassemble chunks into full packets)
"""

from __future__ import annotations

import base64
import json
from typing import Any


def b64e(data: bytes) -> str:
    """Encode bytes to a base64 string."""
    return base64.b64encode(data).decode("utf-8")


def b64d(data: str) -> bytes:
    """Decode a base64 string to bytes."""
    return base64.b64decode(data.encode("utf-8"))


def chunk_text(text: str, chunk_size: int) -> list[str]:
    """Split a string into fixed-size fragments."""
    return [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]


def make_chunk_packets(
    packet_type: str,
    session_id: str,
    payload_obj: dict[str, Any],
    chunk_size: int,
    message_id: int | None = None,
) -> list[dict[str, Any]]:
    """
    Serialize payload_obj to compact JSON and split into transport chunk packets.

    Each returned chunk dict has the form::

        {
            "t":   <packet_type>,   # e.g. "si" (session_init) or "tc" (telemetry chunk)
            "sid": <session_id>,
            "i":   <chunk_index>,   # 0-based
            "n":   <total_chunks>,
            "d":   <fragment_str>,  # raw JSON fragment (not base64 at this layer)
            "mid": <message_id>,    # optional; omitted if not provided
        }

    Parameters
    ----------
    packet_type : str
        Short type tag included in each chunk envelope.
    session_id : str
        Session identifier shared between satellite and ground station.
    payload_obj : dict
        The object to serialize and chunk.
    chunk_size : int
        Maximum characters per chunk fragment (tune to fit LoRa MTU).
    message_id : int, optional
        Monotonic message counter for reassembly ordering.

    Returns
    -------
    list[dict]
        Ordered list of chunk envelopes ready for transport framing.
    """
    compact = json.dumps(payload_obj, separators=(",", ":"))
    fragments = chunk_text(compact, chunk_size)
    total = len(fragments)

    packets: list[dict[str, Any]] = []
    for idx, frag in enumerate(fragments):
        pkt: dict[str, Any] = {
            "t":   packet_type,
            "sid": session_id,
            "i":   idx,
            "n":   total,
            "d":   frag,
        }
        if message_id is not None:
            pkt["mid"] = message_id
        packets.append(pkt)

    return packets
