"""
AegisLEO — Packet Inspection Tool
====================================

Created by: Jamie Grunewald
Date: 2026-03-26
Version: v0.1.0 (stub)

Purpose
-------
Planned CLI tool for offline inspection of captured AegisLEO packet logs.
Intended to help debug framing issues, reassembly failures, and signature
verification problems without running the full pipeline.

Planned functionality
---------------------
- Parse raw transport frames from a binary capture file
- Decode chunk envelopes and display reassembly state
- Verify ML-DSA-65 signatures against the satellite public key
- Decode AES-256-GCM payloads given a known session key (debug mode)
- Display ThreatScore breakdown per packet

Planned usage
-------------
    # Inspect a raw serial capture:
    python tools/packet_inspection.py --input capture.bin --public-key keys/satellite_mldsa_public.key

    # Decode a specific session from a log:
    python tools/packet_inspection.py --log data/telemetry_logs/session_abc123.log

See also
--------
- tools/telemetry_visualizer.py  — visualize decoded telemetry from log files
- groundstation/receiver.py      — live receive + decode pipeline
- docs/protocol_spec.md          — frame and packet format reference
"""

# TODO: implement offline packet inspection and decode tool
