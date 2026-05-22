"""
AegisLEO — Telemetry Sniffer
==============================

Created by: Jamie Grunewald
Date: 2026-03-26
Version: v0.1.0 (stub)

Purpose
-------
Passive capture tool that reads raw transport frames from the LoRa serial
link and saves them to a binary file for offline analysis or replay.

The sniffer does not attempt to decrypt or verify frames — it records the
raw wire bytes exactly as they appear on the link, including frame delimiters
and byte-stuffed length fields. Captured files can be fed into
replay_attack.py or analyzed offline with tools/packet_inspection.py.

This models a passive RF adversary with physical access to the link who
can observe ciphertext but cannot decrypt it or forge signatures.

Planned usage
-------------
    # Capture 20 frames to a file
    python adversary/telemetry_sniffer.py \
        --port /dev/ttyACM0 \
        --output captures/session_001.bin \
        --count 20

    # Capture indefinitely until Ctrl+C
    python adversary/telemetry_sniffer.py \
        --port /dev/ttyACM0 \
        --output captures/live.bin

Output format
-------------
Raw binary: sequence of length-prefixed frames as they appear on the wire.
Each frame: FRAME_START + STUFFED_LENGTH(4+) + PAYLOAD + FRAME_END

See also
--------
- adversary/replay_attack.py      — replay captured frames
- tools/packet_inspection.py      — offline frame decode and analysis
- docs/protocol_spec.md           — transport framing specification
"""

# TODO: implement passive serial frame capture to binary file
