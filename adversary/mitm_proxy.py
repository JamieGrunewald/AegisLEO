"""
AegisLEO — MITM Proxy
=======================

Created by: Jamie Grunewald
Date: 2026-03-26
Version: v0.1.0 (stub)

Purpose
-------
Man-in-the-middle proxy that sits between the satellite LoRa transmitter
and the ground station receiver, forwarding frames while optionally
modifying, dropping, or delaying them.

In the AegisLEO threat model, a MITM adversary on the RF link can:
  - Observe all traffic (ciphertext visible, plaintext is not)
  - Drop packets selectively to cause NACK storms
  - Replay previously seen frames
  - Inject crafted frames (see kali-inj-bridge.py)
  - Introduce artificial delay to test session TTL behavior

What a MITM adversary CANNOT do (by design):
  - Forge valid ML-DSA-65 signatures without the satellite private key
  - Decrypt AES-256-GCM ciphertext without the session key
  - Modify ciphertext without the AEAD tag becoming invalid

Expected detection result
--------------------------
  Modified frames : crypto=REJECTED (AEAD tag invalid or signature fails)
  Dropped frames  : NACK generated, satellite retransmits
  Replayed frames : replay_window=REJECTED

Planned usage
-------------
    python adversary/mitm_proxy.py \
        --sat-port /dev/ttyUSB0 \
        --gs-port /dev/ttyUSB1 \
        --mode drop --drop-rate 0.2

Proxy modes (planned)
---------------------
passthrough : forward all frames unmodified (baseline / traffic analysis)
drop        : randomly drop frames at --drop-rate probability
delay       : add artificial latency to test TTL behavior
modify      : bit-flip random bytes in the payload (triggers AEAD failure)
replay      : capture and re-inject frames (triggers replay window)

See also
--------
- adversary/replay_attack.py     — dedicated replay tool
- adversary/kali-inj-bridge.py   — direct frame injection
- docs/pqc_design.md             — threat model
"""

# TODO: implement MITM proxy for RF link interception and manipulation
