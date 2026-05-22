"""
AegisLEO — Replay Attack Tool
===============================

Created by: Jamie Grunewald
Date: 2026-03-26
Version: v0.1.0 (stub)

Purpose
-------
Captures valid authenticated telemetry frames from the LoRa link and
re-injects them at a later time to test the ground station's replay
protection window (groundstation/replay_window.py).

A replay attack differs from packet injection (kali-inj-bridge.py) in that
the replayed frames carry a VALID ML-DSA-65 signature — they were genuinely
signed by the satellite. The replay window rejects them based on sequence
number state rather than signature failure.

Expected detection result
--------------------------
  Crypto layer : signature=VALID   (genuine packet captured from the link)
  Replay window: REJECTED          (sequence number already seen / too old)
  ThreatScore  : replay_weight × 0.1 contribution

Planned usage
-------------
    # Step 1: capture live frames to a file
    python adversary/telemetry_sniffer.py --output capture.bin --count 10

    # Step 2: replay them after a delay
    python adversary/replay_attack.py --input capture.bin --delay 30

See also
--------
- groundstation/replay_window.py  — sliding window replay protection
- adversary/telemetry_sniffer.py  — frame capture tool
- adversary/kali-inj-bridge.py    — forged frame injection (no valid sig)
- docs/protocol_spec.md           — replay protection specification
"""

# TODO: implement frame capture and replay injection
