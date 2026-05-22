"""
AegisLEO Post-Quantum KEM Helpers

Created by: Jamie Grunewald
Date: 2026-03-23
Version: v0.1.0

Purpose
-------
Provide a small wrapper around ML-KEM using the oqs Python bindings.

This module is responsible for:
- generating ML-KEM keypairs
- encapsulating a shared secret with a public key
- decapsulating a shared secret with a private key

Notes
-----
- This assumes the `oqs` Python package is installed and working.
- ML-KEM-1024 is used here for strong post-quantum key establishment.
- The shared secret returned by ML-KEM should usually be fed into a KDF
  before use as an AES key.
"""

import base64
import oqs
from dataclasses import dataclass
from __future__ import annotations

DEFAULT_KEM_ALG = "ML-KEM-1024"

def b64e(data: bytes) -> str:
    """Encode bytes as base64 text for JSON-friendly transport/storage."""
    return base64.b64encode(data).decode("utf-8")

def b64d(data: str) -> bytes:
    """Decode base64 text back into bytes."""
    return base64.b64decode(data.encode("utf-8"))

@dataclass
class KEMKeyPair:
    """
    Container for an ML-KEM keypair.

    Attributes
    ----------
    algorithm : str
        KEM algorithm name, e.g. ML-KEM-1024
    public_key : bytes
        Public key used by the sender to encapsulate
    private_key : bytes
        Private key used by the receiver to decapsulate
    """

    algorithm: str
    public_key: bytes
    private_key: bytes

@dataclass
class EncapsulationResult:
    """
    Container for ML-KEM encapsulation output.

    Attributes
    ----------
    algorithm : str
        KEM algorithm name
    ciphertext : bytes
        Ciphertext sent to the recipient
    shared_secret : bytes
        Shared secret derived during encapsulation
    """
    algorithm: str
    ciphertext: bytes
    shared_secret: bytes

def generate_keypair(algorithm: str = DEFAULT_KEM_ALG) -> KEMKeyPair:
    """
    Generate a new ML-KEM keypair.

    Parameters
    ----------
    algorithm : str
        KEM algorithm to use. Default is ML-KEM-1024.

    Returns
    -------
    KEMKeyPair
        Generated public/private keypair
    """
    with oqs.KeyEncapsulation(algorithm) as kem:
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()
        return KEMKeyPair(
            algorithm=algorithm,
            public_key=public_key,
            private_key=private_key,
        )

def encapsulate(public_key: bytes, algorithm: str = DEFAULT_KEM_ALG) -> EncapsulationResult:
    """
    Encapsulate a shared secret to the recipient's public key.

    Parameters
    ----------
    public_key : bytes
        Recipient's public key
    algorithm : str
        KEM algorithm to use

    Returns
    -------
    EncapsulationResult
        Ciphertext plus shared secret
    """
    with oqs.KeyEncapsulation(algorithm) as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return EncapsulationResult(
            algorithm=algorithm,
            ciphertext=ciphertext,
            shared_secret=shared_secret,
        )

def decapsulate(ciphertext: bytes, private_key: bytes, algorithm: str = DEFAULT_KEM_ALG) -> bytes:
    """
    Recover the shared secret from ciphertext using the private key.

    Parameters
    ----------
    ciphertext : bytes
        KEM ciphertext received from sender
    private_key : bytes
        Recipient private key
    algorithm : str
        KEM algorithm to use

    Returns
    -------
    bytes
        Recovered shared secret
    """
    with oqs.KeyEncapsulation(algorithm, secret_key=private_key) as kem:
        return kem.decap_secret(ciphertext)
