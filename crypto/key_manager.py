"""
AegisLEO Session Key Manager

Created by: Jamie Grunewald
Date: 2026-03-23
Version: v0.1.0

Purpose
-------
Manage ML-KEM-based session establishment and derive AES-256 session keys.

This module is responsible for:
- creating receiver-side ML-KEM keypairs
- creating initiator-side encapsulation messages
- deriving symmetric AES session keys from the shared secret
- tracking simple session lifecycle metadata

Design
------
Ground station / receiver flow:
1. Generate ML-KEM keypair
2. Share public key with sender
3. Receive KEM ciphertext from sender
4. Decapsulate shared secret
5. Derive AES-256 session key

Satellite / sender flow:
1. Receive receiver public key
2. Encapsulate shared secret
3. Derive AES-256 session key
4. Send KEM ciphertext to receiver
"""

from __future__ import annotations

import base64
import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from crypto.pq_kem import (
    DEFAULT_KEM_ALG,
    KEMKeyPair,
    decapsulate,
    encapsulate,
    generate_keypair,
)


def b64e(data: bytes) -> str:
    """Encode bytes as base64 text."""
    return base64.b64encode(data).decode("utf-8")


def b64d(data: str) -> bytes:
    """Decode base64 text into bytes."""
    return base64.b64decode(data.encode("utf-8"))


def _make_session_id() -> str:
    """Generate a compact session identifier."""
    return hashlib.sha256(os.urandom(32)).hexdigest()[:16]


def derive_aes256_key(
    shared_secret: bytes,
    salt: Optional[bytes] = None,
    info: bytes = b"AegisLEO-AES256-Session-Key",
) -> bytes:
    """
    Derive a 32-byte AES-256 key from an ML-KEM shared secret using HKDF-SHA256.

    Parameters
    ----------
    shared_secret : bytes
        Raw shared secret from ML-KEM.
    salt : bytes | None
        Optional HKDF salt. If omitted, a zero/empty salt is used by HKDF.
    info : bytes
        Context string to separate this derivation from other uses.

    Returns
    -------
    bytes
        32-byte AES-256 key.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)


@dataclass
class SessionState:
    """
    Represents a live symmetric session.

    Attributes
    ----------
    session_id : str
        Logical session identifier.
    algorithm : str
        ML-KEM algorithm used during setup.
    aes_key : bytes
        Derived AES-256 session key.
    created_at : float
        Unix timestamp when session was created.
    expires_at : float
        Unix timestamp when session should expire.
    kem_ciphertext : bytes | None
        KEM ciphertext associated with session establishment.
        Present on initiator side, optional on responder side.
    sequence_out : int
        Outgoing packet sequence counter.
    highest_sequence_in : int
        Highest incoming sequence accepted so far.
    """

    session_id: str
    algorithm: str
    aes_key: bytes
    created_at: float
    expires_at: float
    kem_ciphertext: Optional[bytes] = None
    sequence_out: int = 0
    highest_sequence_in: int = -1

    def is_expired(self, now: Optional[float] = None) -> bool:
        """Return True if the session lifetime has expired."""
        now = time.time() if now is None else now
        return now >= self.expires_at

    def next_sequence(self) -> int:
        """Return the next outbound sequence number and increment the counter."""
        seq = self.sequence_out
        self.sequence_out += 1
        return seq

    def zeroize(self) -> None:
        """
        Best-effort clear of sensitive fields.

        Python cannot guarantee true memory zeroization for immutable bytes,
        but clearing references still helps lifecycle hygiene.
        """
        self.aes_key = b""
        self.kem_ciphertext = None
        self.sequence_out = 0
        self.highest_sequence_in = -1
        self.expires_at = 0.0


@dataclass(frozen=True)
class ReceiverBootstrap:
    """
    Receiver-side bootstrap material.

    This is created by the receiver/ground station and the public key is shared
    with the sender/satellite.
    """

    algorithm: str
    public_key: bytes
    private_key: bytes


@dataclass(frozen=True)
class InitiatorHandshake:
    """
    Initiator-side handshake output.

    The initiator derives the AES key locally and sends the KEM ciphertext to
    the responder so it can recover the same shared secret.
    """

    session: SessionState
    kem_ciphertext: bytes


class KeyManager:
    """
    Manage PQ KEM bootstrapping and AES session establishment.
    """

    def __init__(
        self,
        algorithm: str = DEFAULT_KEM_ALG,
        session_ttl_seconds: int = 3600,
        hkdf_info: bytes = b"AegisLEO-AES256-Session-Key",
    ) -> None:
        self.algorithm = algorithm
        self.session_ttl_seconds = session_ttl_seconds
        self.hkdf_info = hkdf_info

    def create_receiver_bootstrap(self) -> ReceiverBootstrap:
        """
        Generate a new ML-KEM keypair for the receiver/ground station.

        Returns
        -------
        ReceiverBootstrap
            Contains public/private key material.
        """
        kp: KEMKeyPair = generate_keypair(self.algorithm)
        return ReceiverBootstrap(
            algorithm=kp.algorithm,
            public_key=kp.public_key,
            private_key=kp.private_key,
        )

    def create_initiator_session(
        self,
        receiver_public_key: bytes,
        salt: Optional[bytes] = None,
    ) -> InitiatorHandshake:
        """
        Create a sender-side session from the receiver's public key.

        Steps
        -----
        1. Encapsulate to the receiver public key
        2. Derive AES-256 key from the shared secret
        3. Return session + KEM ciphertext

        Returns
        -------
        InitiatorHandshake
            Contains live session state and the ciphertext that must be sent to
            the receiver.
        """
        enc = encapsulate(receiver_public_key, algorithm=self.algorithm)
        aes_key = derive_aes256_key(
            shared_secret=enc.shared_secret,
            salt=salt,
            info=self.hkdf_info,
        )

        now = time.time()
        session = SessionState(
            session_id=_make_session_id(),
            algorithm=enc.algorithm,
            aes_key=aes_key,
            created_at=now,
            expires_at=now + self.session_ttl_seconds,
            kem_ciphertext=enc.ciphertext,
        )

        return InitiatorHandshake(
            session=session,
            kem_ciphertext=enc.ciphertext,
        )

    def create_receiver_session(
        self,
        kem_ciphertext: bytes,
        receiver_private_key: bytes,
        salt: Optional[bytes] = None,
        session_id: Optional[str] = None,
    ) -> SessionState:
        """
        Create a receiver-side session from received KEM ciphertext.

        Steps
        -----
        1. Decapsulate using receiver private key
        2. Derive AES-256 key from the shared secret
        3. Return live session state

        Parameters
        ----------
        kem_ciphertext : bytes
            Ciphertext received from the initiator.
        receiver_private_key : bytes
            Receiver private key generated during bootstrap.
        salt : bytes | None
            Optional HKDF salt.
        session_id : str | None
            Optional externally assigned session ID.

        Returns
        -------
        SessionState
            Receiver-side live session.
        """
        shared_secret = decapsulate(
            ciphertext=kem_ciphertext,
            private_key=receiver_private_key,
            algorithm=self.algorithm,
        )
        aes_key = derive_aes256_key(
            shared_secret=shared_secret,
            salt=salt,
            info=self.hkdf_info,
        )

        now = time.time()
        return SessionState(
            session_id=session_id or _make_session_id(),
            algorithm=self.algorithm,
            aes_key=aes_key,
            created_at=now,
            expires_at=now + self.session_ttl_seconds,
            kem_ciphertext=kem_ciphertext,
        )