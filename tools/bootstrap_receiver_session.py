from pathlib import Path

from crypto.key_manager import KeyManager

OUTDIR = Path("dev_secrets/groundstation")
OUTDIR.mkdir(parents=True, exist_ok=True)

km = KeyManager()
bootstrap = km.create_receiver_bootstrap()

(OUTDIR / "receiver_kem_public.key").write_bytes(bootstrap.public_key)
(OUTDIR / "receiver_kem_private.key").write_bytes(bootstrap.private_key)

print("Ground station KEM bootstrap generated:")
print(f"  Public : {OUTDIR / 'receiver_kem_public.key'}")
print(f"  Private: {OUTDIR / 'receiver_kem_private.key'}")