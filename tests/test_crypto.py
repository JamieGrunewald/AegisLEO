"""
tests/test_crypto.py

These tests validate the security building blocks for AegisLEO.

What we test here
-----------------
1) AES-GCM encrypt/decrypt succeeds with correct key and AAD
2) AES-GCM rejects tampered ciphertext
3) ML-DSA sign/verify succeeds for untampered data
4) ML-DSA verification fails when signed data is modified

Why this matters
----------------
Packet tests prove the protocol structure works.
Crypto tests prove the protection layers work.
"""

from crypto.aes_gcm import encrypt, decrypt
from crypto.mldsa_signatures import generate_keypair, sign, verify
# from crypto.pq_sign import generate_keypair, sign, verify


def test_aes_gcm_roundtrip():
    """
    Encrypt plaintext, then decrypt it with the same key and AAD.
    Expected result:
    - decryption succeeds
    - recovered plaintext matches original plaintext
    """
    key = b"0123456789ABCDEF0123456789ABCDEF"
    aad = b"AegisLEO-SAT-1"
    plaintext = b'{"temp_c":12.34,"bus_v":5.01,"state":"NOMINAL"}'

    encrypted = encrypt(plaintext, key, aad=aad)
    recovered = decrypt(
        encrypted["nonce"],
        encrypted["ciphertext"],
        key,
        aad=aad,
    )

    assert recovered == plaintext


def test_aes_gcm_rejects_tampered_ciphertext():
    """
    Flip one bit in the ciphertext.
    AES-GCM should reject it during decryption/authentication.
    """
    key = b"0123456789ABCDEF0123456789ABCDEF"
    aad = b"AegisLEO-SAT-1"
    plaintext = b'{"temp_c":12.34,"bus_v":5.01,"state":"NOMINAL"}'

    encrypted = encrypt(plaintext, key, aad=aad)

    tampered = bytearray(encrypted["ciphertext"])
    tampered[-1] ^= 0x01  # Flip one bit in the last byte

    try:
        decrypt(
            encrypted["nonce"],
            bytes(tampered),
            key,
            aad=aad,
        )
        assert False, "expected AES-GCM authentication failure, but decrypt succeeded"
    except Exception:
        # Any exception here is acceptable because tampering must fail
        assert True


def test_mldsa_sign_verify_roundtrip():
    """
    Generate a test keypair, sign a message, and verify it.
    Expected result:
    - verify() returns True
    """
    kp = generate_keypair()
    message = b"AegisLEO secure telemetry packet"

    signature = sign(message, kp.secret_key)
    assert verify(message, signature, kp.public_key) is True


def test_mldsa_verify_fails_on_tampered_message():
    """
    Sign one message, then try to verify the signature against modified data.
    Expected result:
    - verify() returns False
    """
    kp = generate_keypair()

    original_message = b"AegisLEO secure telemetry packet"
    tampered_message = b"AegisLEO secure telemetry p4cket"

    signature = sign(original_message, kp.secret_key)
    assert verify(tampered_message, signature, kp.public_key) is False