# AegisLEO

**Hardware-in-the-loop post-quantum satellite telemetry security testbed**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-Raspberry%20Pi%205%20%7C%20Jetson%20Orin-green)
![Crypto](https://img.shields.io/badge/crypto-ML--KEM--1024%20%7C%20ML--DSA--65%20%7C%20AES--256--GCM-orange)

> Presented at **CypherCon 9** — Milwaukee, WI — April 2026

---

## What it is

AegisLEO is a research testbed for evaluating post-quantum cryptographic protections applied to satellite telemetry in a realistic adversarial environment. It implements a full ground-to-satellite link using physical LoRa radio hardware, with a dedicated adversary node that injects spoofed and replayed CCSDS packets to simulate real attack scenarios.

The system is designed around two core questions:

1. Can post-quantum cryptography (ML-KEM + ML-DSA per FIPS 203/204) be made practical on resource-constrained embedded hardware?
2. Can an ML-based anomaly detector meaningfully extend cryptographic verification to catch behavioral attacks that pass signature checks?

---

## Hardware

| Role | Hardware |
|---|---|
| Satellite node | Raspberry Pi 5 |
| Ground station | NVIDIA Jetson Orin Nano Super |
| RF link | Waveshare SX1262 LoRa HAT (both nodes) |
| Adversary node | Kali Linux VM (`darpa-01`) on Proxmox |

The adversary node operates on the same network segment and injects malformed, replayed, and spoofed CCSDS Space Packet Protocol frames to exercise the detection pipeline under realistic threat conditions.

---

## Cryptographic Stack

| Primitive | Algorithm | Standard |
|---|---|---|
| Key encapsulation | ML-KEM-1024 | FIPS 203 |
| Digital signatures | ML-DSA-65 | FIPS 204 |
| Symmetric encryption | AES-256-GCM | NIST |
| Key derivation | HKDF-SHA256 | RFC 5869 |

All post-quantum primitives are provided by [liboqs](https://github.com/open-quantum-safe/liboqs) via the Python bindings in [liboqs-python](https://github.com/open-quantum-safe/liboqs-python). See [docs/pqc_design.md](docs/pqc_design.md) for the full cryptographic design rationale.

---

## Anomaly Detection

A PyTorch autoencoder is trained on nominal telemetry to establish a baseline reconstruction error profile. At runtime, each decrypted telemetry frame is scored against the model. Frames that pass signature verification but exhibit reconstruction error above threshold are flagged as behavioral anomalies.

The composite **ThreatScore** weights three signals:

| Signal | Weight |
|---|---|
| Cryptographic verdict | 0.6 |
| ML anomaly score | 0.3 |
| Replay window status | 0.1 |

---

## Repository Structure

```
AegisLEO/
├── satellite/          # Transmitter — runs on Raspberry Pi 5
├── groundstation/      # Receiver + anomaly pipeline — runs on Jetson Orin
├── adversary/          # Attack tools: replay, fuzzer, MITM proxy, sniffer
├── crypto/             # ML-KEM, ML-DSA, AES-GCM, HKDF key manager
├── ccsds/              # CCSDS Space Packet Protocol framing
├── common/             # Shared telemetry, protocol, logging utilities
├── models/             # PyTorch autoencoder: training pipeline + runtime detector
├── radio/              # LoRa serial driver and radio config
├── experiments/        # Benchmarking: PQC latency, LoRa throughput, packet sizing
├── tools/              # Key generation, session bootstrap, inspection utilities
├── tests/              # pytest suite
├── config/             # YAML config stubs (crypto, radio, telemetry)
└── docs/               # Architecture, PQC design, protocol spec
```

---

## Getting Started

### Prerequisites

- Python 3.10+
- [liboqs](https://github.com/open-quantum-safe/liboqs) compiled and installed
- [liboqs-python](https://github.com/open-quantum-safe/liboqs-python) bindings installed
- Physical hardware (Pi 5 + Jetson Orin + SX1262 LoRa) **or** loopback serial for local testing

### Install

```bash
git clone https://github.com/JamieGrunewald/AegisLEO.git
cd AegisLEO
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

> **Note on liboqs-python:** The `oqs` package is not available on PyPI. Follow the [liboqs-python installation guide](https://github.com/open-quantum-safe/liboqs-python?tab=readme-ov-file#installation) to build and install it before proceeding.

### Generate keys

```bash
python tools/generate_keys.py
```

This produces:
- `keys/satellite_mldsa_public.key` — distribute to ground station
- `keys/satellite_mldsa_secret.key` — stays on the satellite node only
- `dev_secrets/groundstation/receiver_kem_private.key` — stays on ground station
- `dev_secrets/satellite/receiver_kem_public.key` — distribute to satellite node

### Bootstrap a receiver session

```bash
python tools/bootstrap_receiver_session.py
```

### Run

**Satellite node (Pi 5):**
```bash
python -m satellite.transmitter
```

**Ground station (Jetson Orin):**
```bash
python -m groundstation.receiver
```

**Adversary node (optional):**
```bash
python adversary/replay_attack.py
python adversary/packet_fuzzer.py
```

### Run tests

```bash
pytest tests/ -v
```

---

## Roadmap (v2.0)

- [ ] Replace LoRa modules with HackRF One (TX) + RTL-SDR v4 (RX) for over-the-air RF testing
- [ ] GNU Radio integration for Doppler shift and AWGN channel modeling
- [ ] InfluxDB + Grafana observability stack for real-time ThreatScore dashboards
- [ ] Hailo-10H accelerator for on-board LLM-assisted anomaly explanation
- [ ] IEEE Aerospace 2027 paper submission

---

## Author

**Jamie Grunewald**
M.S. Cybersecurity — University of Delaware (NSA CAE-accredited)
U.S. Military Veteran

[GitHub](https://github.com/JamieGrunewald) · [LinkedIn](https://linkedin.com/in/jamiegrunewald)

---

## License

MIT — see [LICENSE](LICENSE)
