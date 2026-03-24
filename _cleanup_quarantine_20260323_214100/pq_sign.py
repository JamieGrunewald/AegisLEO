"""
AegisLEO ML-DSA Signature Utilities

Created by: Jamie Grunewald
Date: 2026-03-08
Version: v0.3.1

Purpose
-------
This file wraps ML-DSA signing and verification using liboqs Python bindings.

What ML-DSA does
----------------
ML-DSA is the post-quantum digital signature standard from FIPS 204.

It helps us answer:
- Did this packet really come from the satellite?
- Was the packet modified?
- Can an attacker forge packets without the secret signing key?

In simple terms
---------------
Satellite:
    signs packet with private key

Ground station:
    verifies signature with public key

If the signature fails:
    reject packet

Important note
--------------
This module depends on the 'oqs' Python package and the underlying liboqs
library being installed correctly.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

import oqs


# ---------------------------------------------------------------------
# Default ML-DSA algorithm
# ---------------------------------------------------------------------
# Common choices:
# - ML-DSA-44
# - ML-DSA-65
# - ML-DSA-87
#
# We are using ML-DSA-65 as a middle-ground demo choice.
DEFAULT_SIG_ALG = "ML-DSA-65"


@dataclass
class SignatureKeypair:
    """
    Simple container for a generated keypair.

    Fields
    ------
    algorithm : str
        Name of the ML-DSA algorithm used.

    public_key : bytes
        The public key. Safe to distribute to verifiers.

    secret_key : bytes
        The private/secret key. Must be protected.
    """
    algorithm: str
    public_key: bytes
    secret_key: bytes


def generate_keypair(algorithm: str = DEFAULT_SIG_ALG) -> SignatureKeypair:
    """
    Generate a new ML-DSA keypair.

    Parameters
    ----------
    algorithm : str
        Signature algorithm name supported by liboqs.

    Returns
    -------
    SignatureKeypair
        Object containing algorithm, public key, and secret key.
    """
    # Create a signer object for the selected algorithm
    with oqs.Signature(algorithm) as signer:
        # generate_keypair() returns the public key
        public_key = signer.generate_keypair()

        # export_secret_key() gives us the private key bytes
        secret_key = signer.export_secret_key()

    return SignatureKeypair(
        algorithm=algorithm,
        public_key=public_key,
        secret_key=secret_key,
    )


def sign(message: bytes, secret_key: bytes, algorithm: str = DEFAULT_SIG_ALG) -> bytes:
    """
    Sign a message using the ML-DSA secret key.

    Parameters
    ----------
    message : bytes
        Exact byte sequence to sign.
        This should be deterministic and stable. That is why we use
        canonical JSON serialization before signing.

    secret_key : bytes
        Private signing key.

    algorithm : str
        Signature algorithm name.

    Returns
    -------
    bytes
        Signature bytes.
    """
    # Create signer using the provided secret key
    with oqs.Signature(algorithm, secret_key) as signer:
        return signer.sign(message)


def verify(
    message: bytes,
    signature: bytes,
    public_key: bytes,
    algorithm: str = DEFAULT_SIG_ALG,
) -> bool:
    """
    Verify a signature using the public key.

    Parameters
    ----------
    message : bytes
        Original message bytes that were signed.

    signature : bytes
        Signature to verify.

    public_key : bytes
        Public key corresponding to the satellite private key.

    algorithm : str
        Signature algorithm name.

    Returns
    -------
    bool
        True if signature is valid, otherwise False.
    """
    # Create verifier object
    with oqs.Signature(algorithm) as verifier:
        return verifier.verify(message, signature, public_key)


def b64e(data: bytes) -> str:
    """
    Base64-encode binary data into text.

    Why we need this
    ----------------
    JSON cannot safely carry raw binary bytes.
    So we convert:
        bytes -> base64 text

    This is useful for:
    - nonce
    - ciphertext
    - signatures
    """
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    """
    Decode base64 text back into raw bytes.
    """
    return base64.b64decode(data.encode("ascii"))