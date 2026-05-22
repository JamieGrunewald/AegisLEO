"""
AegisLEO — CCSDS Packet (Compatibility Shim)
=============================================

Created by: Jamie Grunewald
Date: 2026-03-08
Version: v0.3.1

Purpose
-------
Compatibility shim — re-exports all public symbols from ccsds/frame.py.

During early development, frame-building logic lived in this file. It was
later consolidated into ccsds/frame.py as the canonical module. This shim
preserves backward compatibility for any code that imports from ccsds.packet
(including tests/test_packet.py and tests/test_secure_pipeline.py) without
maintaining a duplicate implementation.

Use ccsds/frame.py for all new code.
"""

from .frame import build_frame, canonical_json_bytes, parse_json_bytes, PROTOCOL_VERSION

__all__ = ["build_frame", "canonical_json_bytes", "parse_json_bytes", "PROTOCOL_VERSION"]
