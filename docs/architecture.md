# AegisLEO — System Architecture

## Overview

AegisLEO is a hardware-in-the-loop testbed that simulates a satellite telemetry downlink with post-quantum cryptographic protection and ML-based anomaly detection. The system comprises three physical nodes and one adversary node, connected over a real RF link.

```
┌─────────────────────┐        LoRa RF        ┌──────────────────────────┐
│  Satellite Node     │ ──────────────────▶   │  Ground Station          │
│  Raspberry Pi 5     │                        │  NVIDIA Jetson Orin Nano │
│                     │ ◀──────────────────    │  Super                   │
│  - ML-KEM-1024 KEM  │     ACK / NACK         │                          │
│  - ML-DSA-65 sign   │                        │  - ML-KEM decapsulate    │
│  - AES-256-GCM enc  │                        │  - ML-DSA-65 verify      │
│  - CCSDS framing    │                        │  - AES-256-GCM decrypt   │
│  - LoRa TX (SX1262) │                        │  - Replay window check   │
└─────────────────────┘                        │  - Autoencoder scoring   │
                                               │  - ThreatScore output    │
         ▲                                     └──────────────────────────┘
         │ injected frames
┌─────────────────────┐
│  Adversary Node     │
│  Kali Linux VM      │
│  (darpa-01, Proxmox)│
│                     │
│  - Replay attack    │
│  - Packet fuzzer    │
│  - MITM proxy       │
│  - Spoofed CCSDS    │
└─────────────────────┘
```

---

## Node Roles

### Satellite Node — Raspberry Pi 5

Simulates an onboard satellite flight computer. Generates synthetic telemetry (temperature, battery, bus voltage/current, orbital position, mode state), signs it with ML-DSA-65, encrypts it with AES-256-GCM using a session key derived via ML-KEM-1024, frames it as CCSDS Space Packets, and transmits over LoRa serial.

Key files: `satellite/transmitter.py`, `crypto/key_manager.py`

### Ground Station — NVIDIA Jetson Orin Nano Super

Receives LoRa frames, reassembles chunked packets, verifies ML-DSA-65 signatures, decapsulates the ML-KEM session key, decrypts the payload, checks the replay window, and scores the telemetry through the autoencoder anomaly detector. Outputs a composite ThreatScore and sends ACK/NACK back to the satellite.

Key files: `groundstation/receiver.py`, `groundstation/reassembly.py`, `models/runtime_detector.py`

### Adversary Node — Kali Linux VM

Injects crafted, replayed, or malformed CCSDS frames to test the detection pipeline. Cannot forge valid ML-DSA-65 signatures (no access to the satellite private key), so injected packets fail crypto verification. Anomalous sensor values in injected payloads also trigger the autoencoder even when the crypto layer is bypassed in test mode.

Key files: `adversary/replay_attack.py`, `adversary/packet_fuzzer.py`, `adversary/kali-inj-bridge.py`

---

## Data Flow

```
[Telemetry sample]
       │
       ▼
[ML-KEM-1024 session key exchange]  ← one-time per session
       │
       ▼
[ML-DSA-65 sign packet core]
       │
       ▼
[AES-256-GCM encrypt with session key]
       │
       ▼
[CCSDS Space Packet framing]
       │
       ▼
[Chunk + byte-stuff for LoRa MTU]
       │
    LoRa RF
       │
       ▼
[Reassemble chunks]
       │
       ▼
[Verify ML-DSA-65 signature]  ── FAIL ──▶ ThreatScore = 1.0, NACK
       │ PASS
       ▼
[AES-256-GCM decrypt]
       │
       ▼
[Replay window check]  ── REPLAY ──▶ ThreatScore += 0.1
       │ FRESH
       ▼
[Autoencoder anomaly score]
       │
       ▼
[Composite ThreatScore]
  crypto_verdict × 0.6
  + ml_score     × 0.3
  + replay_flag  × 0.1
       │
       ▼
[ACK / NACK → satellite]
```

---

## Transport Framing

Each logical packet is chunked to fit the LoRa DTU limit (~240 bytes wire size) and wrapped in a byte-stuffed transport frame:

```
FRAME_START (0x7E)
STUFFED_LENGTH (4 bytes, big-endian, byte-stuffed)
PAYLOAD (JSON chunk)
FRAME_END (0x7F)
```

Byte-stuffing ensures `0x7E`, `0x7F`, and `0x7D` never appear raw in the length field, preventing framing misalignment on a noisy RF link.

---

## v2.0 Planned Changes

- Replace SX1262 LoRa with HackRF One (TX) + RTL-SDR v4 (RX) for true over-the-air testing
- GNU Radio channel model (Doppler, AWGN)
- InfluxDB + Grafana for live ThreatScore dashboards
- Hailo-10H for on-board ML acceleration
