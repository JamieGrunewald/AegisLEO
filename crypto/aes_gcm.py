"""
AegisLEO AES-256-GCM Utilities

Created by: Jamie Grunewald
Date: 2026-03-08
Version: v0.3.1

Purpose
-------
This file provides helper functions for AES-256-GCM encryption and decryption.

What AES-GCM gives us
---------------------
AES-GCM provides:
- Confidentiality  -> hides the telemetry contents
- Integrity        -> detects tampering
- Authenticity of ciphertext structure via auth tag

Important note
--------------
AES-GCM uses a symmetric key.
That means BOTH sides need the same secret key.

For now:
- we use a shared demo key

Later:
- ML-KEM (FIPS 203) will establish the session key properly
"""

from __future__ import annotations

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_key() -> bytes:
    """
    Generate a fresh AES-256 key.

    AES-256 means:
    - 256-bit key
    - 32 bytes total

    Returns
    -------
    bytes
        Random 32-byte AES key.
    """
    return AESGCM.generate_key(bit_length=256)


def encrypt(plaintext: bytes, key: bytes, aad: bytes | None = None) -> dict[str, bytes]:
    """
    Encrypt plaintext using AES-256-GCM.

    Parameters
    ----------
    plaintext : bytes
        The data we want to protect.
        Example: the serialized CCSDS frame.

    key : bytes
        The shared AES key. Must be 32 bytes for AES-256.

    aad : bytes | None
        Additional Authenticated Data.
        This data is NOT encrypted, but it IS integrity-protected.

        If the sender uses AAD, the receiver must use the exact same AAD
        during decryption or the packet will fail authentication.

        In this project we use spacecraft_id as AAD to bind the packet
        to the sending identity context.

    Returns
    -------
    dict[str, bytes]
        Dictionary containing:
        - nonce
        - ciphertext

    About the nonce
    ---------------
    AES-GCM needs a unique nonce for each encryption under the same key.
    Reusing a nonce with the same key is bad. Very bad. Glass-floor bad.

    We generate a random 12-byte nonce, which is the standard size for GCM.
    """
    # Create AESGCM helper object using the provided key
    aesgcm = AESGCM(key)

    # Generate a fresh random nonce (12 bytes is standard for GCM)
    nonce = os.urandom(12)

    # Encrypt the plaintext
    # The returned value includes ciphertext + authentication tag
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    # Return both pieces needed by the receiver
    return {
        "nonce": nonce,
        "ciphertext": ciphertext,
    }


def decrypt(nonce: bytes, ciphertext: bytes, key: bytes, aad: bytes | None = None) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext.

    Parameters
    ----------
    nonce : bytes
        The nonce used during encryption.

    ciphertext : bytes
        The encrypted data including the GCM authentication tag.

    key : bytes
        The same AES key used for encryption.

    aad : bytes | None
        Must match the AAD used during encryption exactly.

    Returns
    -------
    bytes
        The decrypted plaintext.

    What happens if data was tampered with?
    ---------------------------------------
    If the ciphertext, nonce, key, or AAD are wrong,
    AES-GCM will raise an exception instead of returning bad plaintext.

    That is one of the reasons GCM is so useful.
    """
    # Rebuild AES-GCM helper object with the same key
    aesgcm = AESGCM(key)

    # Attempt decryption
    # If validation fails, this line raises an exception
    return aesgcm.decrypt(nonce, ciphertext, aad)