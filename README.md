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

A PyTorch sequence autoencoder is trained on nominal telemetry to establish a baseline reconstruction error profile. At runtime, each decrypted telemetry frame is scored against the model. Frames that pass signature verification but exhibit reconstruction error above threshold are flagged as behavioral anomalies.

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
│   ├── transmitter.py          # Active: LoRa + PQC + chunked framing (v0.13.0)
│   └── transmitter_legacy.py  # Historical: early LoRa version (reference only)
├── groundstation/      # Receiver + detection pipeline — runs on Jetson Orin
│   ├── receiver.py             # Active: full secure receive loop
│   ├── reassembly.py           # Chunk reassembly (ReassemblyFactory)
│   ├── replay_window.py        # Sliding replay protection window
│   └── feature_logger.py      # ML training data collection (CSV)
├── adversary/          # Attack tools for detection pipeline testing
│   ├── kali-inj-bridge.py     # Demo injection: spike / drift / flatline profiles
│   ├── replay_attack.py        # Packet replay
│   ├── packet_fuzzer.py        # Malformed frame injection
│   └── mitm_proxy.py           # MITM proxy
├── crypto/             # Post-quantum cryptographic primitives
│   ├── pq_kem.py               # ML-KEM-1024 (FIPS 203)
│   ├── mldsa_signatures.py     # ML-DSA-65 (FIPS 204)
│   ├── aes_gcm.py              # AES-256-GCM
│   └── key_manager.py          # Session key establishment + HKDF
├── ccsds/              # CCSDS Space Packet Protocol framing
├── common/             # Shared: telemetry model, chunking, protocol, logging
├── models/             # Anomaly detection
│   ├── generate_normal_dataset.py  # Synthetic training data generator
│   ├── window_dataset.py           # Sliding window dataset builder
│   ├── train_seq_autoencoder.py    # Autoencoder training script
│   └── runtime_detector.py         # Live inference interface
├── radio/              # LoRa radio abstraction (v2.0 stub)
├── experiments/        # PQC benchmarks, LoRa throughput, packet sizing
├── tools/              # Key generation, session bootstrap, inspection utilities
├── tests/              # pytest suite
├── config/             # Runtime configuration (crypto, radio, telemetry)
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

**Step 1 — ML-DSA-65 signing keypair (satellite node):**
```bash
python tools/generate_keys.py
```
Produces `keys/satellite_mldsa_secret.key` (Pi only) and `keys/satellite_mldsa_public.key` (copy to Jetson).

**Step 2 — ML-KEM-1024 KEM keypair (ground station):**
```bash
python tools/bootstrap_receiver_session.py
```
Produces `dev_secrets/groundstation/receiver_kem_private.key` (Jetson only) and `dev_secrets/satellite/receiver_kem_public.key` (copy to Pi).

### Run

**Satellite node (Pi 5):**
```bash
python -m satellite.transmitter
```

**Ground station (Jetson Orin):**
```bash
python -m groundstation.receiver
```

**Adversary node (Kali VM):**
```bash
python adversary/kali-inj-bridge.py --profile spike
python adversary/replay_attack.py
python adversary/packet_fuzzer.py
```

### Train the anomaly detector

```bash
# Generate nominal telemetry dataset
python -m models.generate_normal_dataset

# Train the sequence autoencoder
python -m models.train_seq_autoencoder
```

Trained model saved to `models/seq_autoencoder.pt`. Update `config/telemetry.yaml` with the output threshold.

### Run tests

```bash
pytest tests/ -v
```

---

## Roadmap (v2.0)

**In progress (stubs in repo):**
- [ ] `radio/lora_serial.py` — LoRa serial abstraction layer for HackRF/RTL-SDR migration
- [ ] `groundstation/reassembly.py` → `ReassemblyFactory` extraction and standalone testing
- [ ] `models/telemetry_anomaly_model.py` — unified model interface replacing rule-based detector
- [ ] `models/training_pipeline.py` — end-to-end training orchestration script

**Planned:**
- [ ] Replace SX1262 LoRa with HackRF One (TX) + RTL-SDR v4 (RX) for over-the-air RF testing
- [ ] GNU Radio integration for Doppler shift and AWGN channel modeling
- [ ] InfluxDB + Grafana observability stack for real-time ThreatScore dashboards
- [ ] Hailo-10H accelerator for on-board LLM-assisted anomaly explanation
- [ ] IEEE Aerospace 2027 paper submission

---

## Documentation

| Doc | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | System diagram, node roles, data flow, transport framing |
| [docs/pqc_design.md](docs/pqc_design.md) | Algorithm selection, key lifecycle, threat model |
| [docs/protocol_spec.md](docs/protocol_spec.md) | Packet types, session state machine, CCSDS alignment |

---

## Author

**Jamie Grunewald**
M.S. Cybersecurity — University of Delaware (NSA CAE-accredited)
U.S. Military Veteran

[GitHub](https://github.com/JamieGrunewald) · [LinkedIn](https://linkedin.com/in/jamiegrunewald)

---

## License

MIT — see [LICENSE](LICENSE)
