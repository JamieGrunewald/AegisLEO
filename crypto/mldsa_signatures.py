"""
AegisLEO ML-DSA Signature Utilities (Noob-Friendly Version)

Created by: Jamie Grunewald
Version: v0.4.0

Purpose
-------
This file handles digital signatures using ML-DSA (post-quantum).

Why this matters
----------------
We want to guarantee:
- The satellite really sent this data (authenticity)
- The data was not modified (integrity)
- Attackers cannot forge packets (non-repudiation)

How it works (simple view)
--------------------------
Satellite:
    signs message with PRIVATE key

Ground station:
    verifies message with PUBLIC key

If verification fails:
    reject the packet immediately
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

import oqs

__all__ = ["generate_keypair", "sign", "verify", "b64e", "b64d", "SignatureKeypair"]

# ---------------------------------------------------------------------
# COMPATIBILITY LAYER (VERY IMPORTANT)
# ---------------------------------------------------------------------
def _get_signature_class():
    """
    Different versions of the oqs Python library expose the Signature class
    in different places.

    Some environments:
        oqs.Signature

    Others:
        oqs.oqs.Signature

    This function finds the correct one dynamically so our code works everywhere.
    """
    # Case 1: direct access
    if hasattr(oqs, "Signature"):
        return oqs.Signature

    # Case 2: nested access
    if hasattr(oqs, "oqs") and hasattr(oqs.oqs, "Signature"):
        return oqs.oqs.Signature

    # If neither exists, we cannot proceed
    raise RuntimeError("No compatible oqs Signature class found")


# Store the correct class once so we don't check repeatedly
SignatureClass = _get_signature_class()


# ---------------------------------------------------------------------
# DEFAULT ALGORITHM
# ---------------------------------------------------------------------
DEFAULT_SIG_ALG = "ML-DSA-65"


# ---------------------------------------------------------------------
# KEYPAIR STRUCTURE
# ---------------------------------------------------------------------
@dataclass
class SignatureKeypair:
    """
    Simple container for keys.

    public_key:
        Share this with the receiver

    secret_key:
        Keep this safe on the satellite ONLY
    """
    algorithm: str
    public_key: bytes
    secret_key: bytes


# ---------------------------------------------------------------------
# KEY GENERATION
# ---------------------------------------------------------------------
def generate_keypair(algorithm: str = DEFAULT_SIG_ALG) -> SignatureKeypair:
    """
    Generate a new ML-DSA keypair.

    This would typically be done once and saved to disk.
    """
    with SignatureClass(algorithm) as signer:
        # Generates BOTH keys internally
        public_key = signer.generate_keypair()

        # Export private key (must be protected)
        secret_key = signer.export_secret_key()

    return SignatureKeypair(
        algorithm=algorithm,
        public_key=public_key,
        secret_key=secret_key,
    )


# ---------------------------------------------------------------------
# SIGNING
# ---------------------------------------------------------------------
def sign(message: bytes, secret_key: bytes, algorithm: str = DEFAULT_SIG_ALG) -> bytes:
    """
    Sign a message using the private key.

    IMPORTANT:
    - Message MUST be deterministic (we use canonical JSON)
    - Same input must always produce the same signature verification result
    """
    with SignatureClass(algorithm, secret_key) as signer:
        return signer.sign(message)


# ---------------------------------------------------------------------
# VERIFICATION
# ---------------------------------------------------------------------
def verify(
    message: bytes,
    signature: bytes,
    public_key: bytes,
    algorithm: str = DEFAULT_SIG_ALG,
) -> bool:
    """
    Verify a signature using the public key.

    Returns:
        True  -> valid signature
        False -> invalid or error

    We wrap this in try/except because different oqs versions
    may throw slightly different exceptions.
    """
    try:
        with SignatureClass(algorithm) as verifier:
            return verifier.verify(message, signature, public_key)

    except Exception as e:
        # We NEVER crash the pipeline on signature failure
        print(f"[CRYPTO] verify error: {e}")
        return False


# ---------------------------------------------------------------------
# BASE64 HELPERS
# ---------------------------------------------------------------------
def b64e(data: bytes) -> str:
    """
    Convert raw bytes → safe string for JSON transport.
    """
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    """
    Convert base64 string → raw bytes.
    """
    return base64.b64decode(data.encode("ascii"))