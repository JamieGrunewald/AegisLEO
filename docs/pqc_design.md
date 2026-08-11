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
  Public key is pre-provisioned to the satellite (out-of-band)

Per session:
  Satellite performs ML-KEM encapsulation → (ciphertext, shared_secret)
  Satellite sends ciphertext inside a session_init packet
  Ground station decapsulates → shared_secret
  Both sides derive AES-256 key via HKDF-SHA256(shared_secret, salt, info)

Per packet:
  Satellite signs canonical JSON of the packet core with ML-DSA-65
  Satellite encrypts the signed packet with the session AES key
  Ground station decrypts, then verifies the ML-DSA-65 signature
```

### Key Storage

| Key                            | Location                          | Notes                          |
|--------------------------------|-----------------------------------|--------------------------------|
| `satellite_mldsa_secret.key`   | Satellite only (`keys/`)          | Never leaves the Pi 5          |
| `satellite_mldsa_public.key`   | Ground station (`keys/`)          | Public                         |
| `receiver_kem_private.key`     | Ground station only (`dev_secrets/`) | Never leaves the Jetson     |
| `receiver_kem_public.key`      | Satellite (`dev_secrets/satellite/`) | Public                      |

All secret material is excluded from version control via `.gitignore`. Fresh keys are generated with the scripts in `tools/`.

---

## Implementation

Post-quantum primitives are supplied by [liboqs](https://github.com/open-quantum-safe/liboqs) through the [liboqs-python](https://github.com/open-quantum-safe/liboqs-python) bindings.

| Module                        | Responsibility                              |
|-------------------------------|---------------------------------------------|
| `crypto/pq_kem.py`            | ML-KEM-1024 keygen / encapsulate / decapsulate |
| `crypto/mldsa_signatures.py`  | ML-DSA-65 keygen / sign / verify            |
| `crypto/key_manager.py`       | Session establishment + HKDF                |
| `crypto/aes_gcm.py`           | AES-256-GCM encrypt / decrypt               |

---

## Performance Observations

On the Raspberry Pi 5 and Jetson Orin Nano the chosen parameter sets are fast enough for low-rate telemetry:

- ML-KEM encapsulate + decapsulate: roughly 5–15 ms per session
- ML-DSA-65 sign: roughly 10–30 ms per packet (load-dependent)

Session establishment is a one-time cost. After the AES session key is derived, per-packet overhead is dominated by AES-GCM and is negligible at the testbed’s telemetry cadence. High-rate applications would benefit from hardware acceleration.

Benchmark scripts live in `experiments/`.

---

## Threat Model

| Threat                              | Mitigation                                      |
|-------------------------------------|-------------------------------------------------|
| Passive eavesdropping               | AES-256-GCM                                     |
| Quantum key recovery                | ML-KEM-1024                                     |
| Packet forgery                      | ML-DSA-65 signatures                            |
| Replay                              | Sliding replay window                           |
| Behavioral anomaly (crypto passes)  | Independent sequence autoencoder                |
| Harvest-now-decrypt-later           | Post-quantum session keys                       |

The cryptographic layer and the ML anomaly layer are intentionally independent. Compromise or bypass of one does not disable the other.
