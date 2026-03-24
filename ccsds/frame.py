"""
AegisLEO CCSDS-Style Frame Helpers

Created by: Jamie Grunewald
Date: 2026-03-08
Version: v0.3.1

Purpose
-------
This file builds and parses a simple CCSDS-inspired telemetry frame.

Important:
----------
KEEP IN MIND - This is NOT a full official CCSDS implementation.
It is a learning-friendly, project-specific frame structure inspired by CCSDS.

Why this file exists
--------------------
Instead of sending random strings over LoRa like:

    "temp=12.3"

we will send a more  structured packet like:

    {
        "version": 1,
        "spacecraft_id": "AegisLEO-SAT-1",
        "sequence": 7,
        "timestamp": 1772930000,
        "apid": 100,
        "payload": {
            "temp_c": 12.3,
            "bus_v": 5.01
        }
    }

That structure makes it easier to:
- track packet order
- identify the sender
- add crypto later
- log telemetry cleanly
- feed the ML pipeline
"""

from __future__ import annotations

import json
import time
from typing import Any


# ---------------------------------------------------------------------
# Protocol version
# ---------------------------------------------------------------------
# This lets us version our telemetry format.
# If we change the frame structure later, we can bump this number.
PROTOCOL_VERSION = 1


def build_frame(
    spacecraft_id: str,
    sequence: int,
    apid: int,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """
    Build a telemetry frame as a Python dictionary.

    Parameters
    ----------
    spacecraft_id : str
        A logical identifier for the sending node.
        Example: "AegisLEO-SAT-1"

    sequence : int
        Packet counter that increases by 1 each transmission.
        This helps detect packet loss or out-of-order delivery.

    apid : int
        Application Process Identifier.
        In big-boy space systems this helps identify what type of
        telemetry or subsystem produced the packet.
        For now we use it mainly as a label.

    payload : dict[str, Any]
        The actual telemetry data.
        Example:
            {
                "temp_c": 13.4,
                "bus_v": 5.02,
                "state": "NOMINAL"
            }

    Returns
    -------
    dict[str, Any]
        A complete telemetry frame dictionary.
    """
    return {
        # Version of OUR telemetry protocol
        "version": PROTOCOL_VERSION,

        # Which spacecraft / node sent this packet
        "spacecraft_id": spacecraft_id,

        # Packet sequence number
        "sequence": sequence,

        # Current Unix epoch timestamp in UTC seconds
        "timestamp": int(time.time()),

        # Logical application identifier
        "apid": apid,

        # Actual telemetry content
        "payload": payload,
    }


def canonical_json_bytes(data: dict[str, Any]) -> bytes:
    """
    Convert a dictionary into deterministic JSON bytes.

    Why this matters
    ----------------
    When we sign or verify data, the bytes must match EXACTLY.

    These two JSON objects may look the same to a human:

        {"a":1,"b":2}
        {"b":2,"a":1}

    But their raw text bytes are different unless we force a consistent order.

    So we use:
    - sort_keys=True      -> always sort keys alphabetically
    - separators=(",", ":") -> remove extra spaces for stable output

    Returns
    -------
    bytes
        UTF-8 encoded deterministic JSON.
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")


def parse_json_bytes(raw: bytes) -> dict[str, Any]:
    """
    Parse raw UTF-8 JSON bytes back into a Python dictionary.

    Parameters
    ----------
    raw : bytes
        Raw bytes received after decryption.

    Returns
    -------
    dict[str, Any]
        Parsed telemetry frame.
    """
    return json.loads(raw.decode("utf-8"))