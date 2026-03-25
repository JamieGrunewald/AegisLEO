"""
AegisLEO Key Generation Utility

Created by: Jamie Grunewald
Date: 2026-03-24
Version: v0.1.0

Purpose
-------
Generate ML-DSA signing keys for the satellite node.

What this script does
---------------------
1. Creates the local keys/ directory if it does not exist
2. Generates a fresh ML-DSA keypair
3. Saves:
   - satellite_mldsa_secret.key
   - satellite_mldsa_public.key

Why this matters
----------------
The satellite uses the private key to sign outbound packets.
The ground station uses the public key to verify that packets
came from the expected sender.

Important
---------
- Keep the private key on the Raspberry Pi only
- Copy the public key to the Orin ground station
- Do not commit private keys to GitHub
"""

from __future__ import annotations

from pathlib import Path

import oqs


# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------
ALGORITHM = "ML-DSA-65"
KEYS_DIR = Path("keys")

PUBLIC_KEY_PATH = KEYS_DIR / "satellite_mldsa_public.key"
PRIVATE_KEY_PATH = KEYS_DIR / "satellite_mldsa_secret.key"


def main() -> None:
    """
    Generate a fresh ML-DSA keypair and save it to disk.
    """
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    with oqs.Signature(ALGORITHM) as signer:
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()

    PUBLIC_KEY_PATH.write_bytes(public_key)
    PRIVATE_KEY_PATH.write_bytes(private_key)

    print("Generated ML-DSA keypair successfully.")
    print(f"Algorithm : {ALGORITHM}")
    print(f"Public key: {PUBLIC_KEY_PATH}")
    print(f"Private key: {PRIVATE_KEY_PATH}")
    print("")
    print("Distribution guidance:")
    print("- Copy satellite_mldsa_secret.key to the Raspberry Pi only")
    print("- Copy satellite_mldsa_public.key to the Orin only")


if __name__ == "__main__":
    main()