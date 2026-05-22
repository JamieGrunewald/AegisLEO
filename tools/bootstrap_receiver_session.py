"""
AegisLEO — Ground Station KEM Bootstrap
=========================================

Created by: Jamie Grunewald
Date: 2026-03-24
Version: v0.1.0

Purpose
-------
Generates the ML-KEM-1024 keypair for the ground station receiver and saves
both keys to dev_secrets/groundstation/. Run this once on the Jetson Orin
before starting a session.

What this produces
------------------
dev_secrets/groundstation/receiver_kem_public.key
    The ground station's ML-KEM public key. Copy this to the satellite node
    so it can encapsulate session keys to the ground station.

dev_secrets/groundstation/receiver_kem_private.key
    The ground station's ML-KEM private key. Keep this on the Jetson only.
    Never commit or distribute this file.

Relationship to generate_keys.py
---------------------------------
generate_keys.py   → ML-DSA-65 signing keypair  (satellite signs packets)
bootstrap_receiver_session.py → ML-KEM-1024 KEM keypair (ground station decapsulates)

Both are required before running the full pipeline.

Usage
-----
    python tools/bootstrap_receiver_session.py

Run from the repo root directory.
"""

from __future__ import annotations

from pathlib import Path

from crypto.key_manager import KeyManager

OUTDIR = Path("dev_secrets/groundstation")


def main() -> None:
    OUTDIR.mkdir(parents=True, exist_ok=True)

    km = KeyManager()
    bootstrap = km.create_receiver_bootstrap()

    (OUTDIR / "receiver_kem_public.key").write_bytes(bootstrap.public_key)
    (OUTDIR / "receiver_kem_private.key").write_bytes(bootstrap.private_key)

    print("Ground station KEM bootstrap complete.")
    print(f"  Public : {OUTDIR / 'receiver_kem_public.key'}  ← copy to satellite node")
    print(f"  Private: {OUTDIR / 'receiver_kem_private.key'}  ← keep on Jetson only")
    print()
    print("Next step: copy receiver_kem_public.key to dev_secrets/satellite/ on the Pi.")


if __name__ == "__main__":
    main()
