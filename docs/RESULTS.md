# AegisLEO — Measured Results & Observations

This document records concrete measurements and qualitative observations from the working testbed. Numbers are from the configuration used for the CypherCon 9 demonstration and subsequent lab runs.

## Cryptographic Overhead

| Item                              | Approximate Size / Cost          |
|-----------------------------------|----------------------------------|
| ML-KEM-1024 ciphertext            | 1 568 bytes                      |
| ML-DSA-65 signature               | 3 309 bytes                      |
| Full session_init packet          | ≈ 6 716 bytes                    |
| Chunks required (240-byte LoRa)   | 42                               |
| Session establishment latency     | 5–15 ms (KEM) + framing/TX time  |
| Per-packet ML-DSA-65 sign         | 10–30 ms (Pi 5, load-dependent)  |

After session establishment, per-packet cost is dominated by AES-256-GCM and is negligible at the testbed’s telemetry rate.

## Anomaly Detection

- Model: sequence autoencoder (11 → 32 → 16 → 32 → 11)
- Training: 2 000 nominal telemetry samples
- Threshold: mean + 3σ ≈ **5.27** (auto-tuned)
- Nominal scores observed in operation: typically 0.9–3.0
- Adversarial injections (temperature 85 °C, battery 12 %, bus voltage 2.1 V, etc.): scores often > 100 and in some runs > 800

The cryptographic layer rejected all forged signatures before the ML layer was invoked. When the crypto layer was bypassed for testing, the autoencoder still flagged the anomalous sensor values.

## Link Behavior

- Operated successfully under approximately 20 % packet loss
- Session initialization completed across multiple NACK rounds
- Chunk + NACK reassembly recovered missing segments without full retransmission of the large session_init packet

## Qualitative Lessons

- Near-field RF saturation can produce complete receive failure even when the software is correct; geometry matters.
- Inconsistent timeout constants across modules can silently drop sessions; shared configuration is essential.
- Post-quantum ciphertext and signature sizes are manageable with proper chunking, but they change the character of the link compared with classical ECDH/ECDSA.
- Independent behavioral detection adds meaningful defense-in-depth against the post-breach case in which an adversary can produce valid signatures or has compromised the signing key.
