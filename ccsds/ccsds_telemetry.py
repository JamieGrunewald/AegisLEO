"""
AegisLEO — CCSDS Telemetry Types (stub)
=========================================

Created by: Jamie Grunewald
Date: 2026-03-26
Version: v0.1.0 (stub)

Purpose
-------
Planned home for CCSDS-aligned telemetry type definitions — structured
representations of telemetry packet subtypes beyond the generic frame
format in ccsds/frame.py.

In the current pipeline, telemetry content is handled as a plain Python
dict in the payload field of each frame. This module is reserved for v2.0
work where telemetry types may be formalized with dataclasses or named
tuples aligned more closely to CCSDS Application Data Unit conventions.

Planned contents
----------------
- TelemetryPacket dataclass (housekeeping, science, status subtypes)
- Structured payload validators per APID
- CCSDS Secondary Header support (TAI timestamp, sequence flags)

See also
--------
- ccsds/frame.py          — active frame build/parse functions
- common/telemetry.py     — Telemetry dataclass used throughout the pipeline
- docs/protocol_spec.md   — current packet format specification
"""

# TODO: implement CCSDS telemetry type definitions for v2.0
