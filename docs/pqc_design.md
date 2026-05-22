# AegisLEO — Post-Quantum Cryptography Design

## Motivation

Classical key exchange (RSA, ECDH) and digital signatures (ECDSA) are vulnerable to Cryptographically Relevant Quantum Computers (CRQCs) via Shor's algorithm. Satellite systems face an amplified risk: long operational lifetimes mean data captured today under "harvest now, decrypt later" attacks could be decrypted once quantum hardware matures. AegisLEO applies NIST-standardized post-quantum primitives to the telemetry downlink to evaluate their feasibility on resource-constrained embedded hardware.

---

## Algorithm Selection

| Role | Algorithm | Standard | Security Level |
|---|---|---|---|
| Key encapsulation | ML-KEM-1024 | FIPS 203 | Category 5 (≥256-bit quantum) |
| Digital signatures | ML-DSA-65 | FIPS 204 | Category 3 (≥192-bit quantum) |
| Symmetric encryption | AES-256-GCM | NIST SP 800-38D | 256-bit |
| Key derivation | HKDF-SHA256 | RFC 5869 | — |

**ML-KEM-1024** (Module Lattice Key Encapsulation Mechanism) replaces ECDH for session key establishment. The ground station generates a KEM keypair; the satellite encapsulates a shared secret to the ground station's public key. The shared secret is fed into HKDF-SHA256 to derive the AES-256 session key.

**ML-DSA-65** (Module Lattice Digital Signature Algorithm) replaces ECDSA for packet authentication. The satellite holds a long-term signing keypair. Each telemetry packet's canonical JSON core is signed before encryption. The ground station verifies the signature after decryption.

**AES-256-GCM** provides authenticated symmetric encryption. The AEAD tag catches any bit-level tampering that survives the signature check (e.g. ciphertext manipulation before decryption).

---

## Key Lifecycle

```
Boot / session start:
  Ground station generates ML-KEM-1024 keypair
  Public key distributed to satellite (out-of-band, pre-provisioned)

Per session:
  Satellite encapsulates shared_secret → (ciphertext, shared_secret)
  Satellite sends ciphertext to ground station in session_init packet
  Ground station decapsulates → shared_secret
  Both sides derive AES-256 key via HKDF-SHA256(shared_secret, salt, info)

Per packet:
  Satellite signs canonical_json(packet_core) with ML-DSA-65 secret key
  Satellite encrypts signed packet with AES-256-GCM session key
  Ground station decrypts, then verifies ML-DSA-65 signature
```

### Key Storage

| Key | Location | Notes |
|---|---|---|
| `satellite_mldsa_secret.key` | Satellite node only (`keys/`) | Never leaves Pi 5 |
| `satellite_mldsa_public.key` | Ground station (`keys/`) | Public — safe to distribute |
| `receiver_kem_private.key` | Ground station only (`dev_secrets/`) | Never leaves Jetson |
| `receiver_kem_public.key` | Satellite node (`dev_secrets/satellite/`) | Public — safe to distribute |

All key files are excluded from version control via `.gitignore`. Generate fresh keys with `python tools/generate_keys.py`.

---

## Implementation

All post-quantum primitives are provided by [liboqs](https://github.com/open-quantum-safe/liboqs) (Open Quantum Safe project) via the [liboqs-python](https://github.com/open-quantum-safe/liboqs-python) bindings. liboqs implements FIPS 203 and FIPS 204 using the reference implementations with optional AVX2 optimization.

Key wrapper modules:
- `crypto/pq_kem.py` — ML-KEM-1024 keygen, encapsulate, decapsulate
- `crypto/mldsa_signatures.py` — ML-DSA-65 keygen, sign, verify
- `crypto/key_manager.py` — end-to-end session key establishment + HKDF derivation
- `crypto/aes_gcm.py` — AES-256-GCM encrypt/decrypt via `cryptography` library

---

## Performance Notes

ML-KEM and ML-DSA operations on the Raspberry Pi 5 (ARM Cortex-A76) and Jetson Orin Nano (ARM Cortex-A78AE) are fast enough for a low-rate telemetry downlink. Session key exchange (ML-KEM encapsulate + decapsulate) adds ~5–15ms per session. Per-packet ML-DSA-65 signing adds ~10–30ms depending on load. These costs are acceptable at AegisLEO's telemetry cadence but would require hardware acceleration (e.g. Hailo-10H) for high-rate applications.

Benchmark scripts: `experiments/pqc_benchmarks.py`

---

## Threat Model

| Threat | Mitigation |
|---|---|
| Passive eavesdropping | AES-256-GCM encryption |
| Key recovery via quantum computer | ML-KEM-1024 (post-quantum KEM) |
| Packet forgery | ML-DSA-65 signatures |
| Replay attack | Sliding replay window (`groundstation/replay_window.py`) |
| Behavioral anomaly (passes crypto) | Autoencoder ThreatScore |
| Harvest now, decrypt later | ML-KEM session keys — quantum-safe |
