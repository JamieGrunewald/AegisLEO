"""
crypto/aes_gcm.py

AES-GCM provides:
- Confidentiality (encryption)
- Integrity + authenticity (authentication tag)

Important terms:
- Key: 32 bytes for AES-256
- Nonce: 12 bytes recommended for GCM (must be UNIQUE per key!)
- AAD (Additional Authenticated Data): data that is NOT encrypted but IS authenticated.
  If AAD changes, tag verification fails.

In our design:
- We keep the packet header unencrypted so the ground station can log APID/SEQ/TS.
- We authenticate the header by using it as AAD.
- We encrypt the payload (JSON telemetry bytes).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple
import os

from Cryptodome.Cipher import AES


NONCE_LEN = 12          # recommended nonce length for GCM
TAG_LEN = 16            # 128-bit authentication tag


@dataclass(frozen=True)
class GcmBlob:
    """
    Container for AES-GCM output.
    """
    nonce: bytes
    ciphertext: bytes
    tag: bytes


def generate_key() -> bytes:
    """
    Generate a random 32-byte AES-256 key.
    Store this securely (env var, vault, etc). For the demo we keep it simple.
    """
    return os.urandom(32)


def encrypt_aes_gcm(key: bytes, plaintext: bytes, aad: bytes) -> GcmBlob:
    """
    Encrypt plaintext using AES-GCM.

    Parameters
    ----------
    key : bytes
        32-byte key for AES-256
    plaintext : bytes
        data to encrypt (telemetry payload)
    aad : bytes
        authenticated but unencrypted data (packet header)

    Returns
    -------
    GcmBlob (nonce, ciphertext, tag)
    """
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")

    nonce = os.urandom(NONCE_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return GcmBlob(nonce=nonce, ciphertext=ciphertext, tag=tag)


def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
    """
    Decrypt + verify AES-GCM.

    Raises ValueError if authentication fails (wrong key, tampered data, wrong AAD, etc).
    """
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be {NONCE_LEN} bytes")
    if len(tag) != TAG_LEN:
        raise ValueError(f"tag must be {TAG_LEN} bytes")

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext