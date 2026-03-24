"""
AegisLEO Post-Quantum Signature Utilities

Created by: Jamie Grunewald
Date: 2026-03-19
Version: v0.3.2

Purpose
-------
This module handles ML-DSA signing and verification.

Why this matters
----------------
Encryption protects secrecy.
Signatures protect identity and integrity.

In this project:
- the satellite signs the packet
- the ground station verifies the signature

If signature verification fails, the packet should be rejected.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

import oqs


# Default ML-DSA variant for this lab
DEFAULT_SIG_ALG = "ML-DSA-65"


@dataclass
class SignatureKeypair:
    """
    Small container for a public/private keypair.
    """
    algorithm: str
    public_key: bytes
    secret_key: bytes


def generate_keypair(algorithm: str = DEFAULT_SIG_ALG) -> SignatureKeypair:
    """
    Generate a new ML-DSA keypair.

    Returns
    -------
    SignatureKeypair
        Contains:
        - algorithm name
        - public key
        - secret key
    """
    with oqs.Signature(algorithm) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()

    return SignatureKeypair(
        algorithm=algorithm,
        public_key=public_key,
        secret_key=secret_key,
    )


def sign(message: bytes, secret_key: bytes, algorithm: str = DEFAULT_SIG_ALG) -> bytes:
    """
    Sign raw bytes with the private key.
    """
    with oqs.Signature(algorithm, secret_key) as signer:
        return signer.sign(message)


def verify(
    message: bytes,
    signature: bytes,
    public_key: bytes,
    algorithm: str = DEFAULT_SIG_ALG,
) -> bool:
    """
    Verify a signature with the public key.

    Returns
    -------
    bool
        True if valid, False otherwise.
    """
    with oqs.Signature(algorithm) as verifier:
        return verifier.verify(message, signature, public_key)


def b64e(data: bytes) -> str:
    """
    Convert bytes to base64 text for JSON transport.
    """
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    """
    Convert base64 text back into raw bytes.
    """
    return base64.b64decode(data.encode("ascii"))