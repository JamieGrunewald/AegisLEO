"""
AegisLEO — Session State
=========================

Created by: Jamie Grunewald
Date: 2026-03-23
Version: v0.1.0

Purpose
-------
Holds the ephemeral cryptographic state for one AegisLEO session — the
ML-KEM shared secret, the derived AES-256 session key, and bookkeeping
metadata (session ID, creation time, last sequence number).

A new SessionState is created at the start of each session after the
ML-KEM key exchange completes. It is held in memory only and never
persisted to disk.

Note: In the current pipeline, session state is managed directly inside
groundstation/receiver.py and satellite/transmitter.py. This class is
available for future refactoring into a dedicated session manager.

Used by
-------
- crypto/key_manager.py   (creates SessionState after KEM exchange)
- tests/test_session_key_pipeline.py
"""

from __future__ import annotations

import time


class SessionState:
    """
    Ephemeral cryptographic session context.

    Attributes
    ----------
    session_id : str
        Unique session identifier (16-char hex string).
    shared_secret : bytes
        Raw shared secret from ML-KEM decapsulation. Used only as
        input to HKDF — never transmitted or logged.
    aes_key : bytes
        32-byte AES-256 session key derived from shared_secret via
        HKDF-SHA256. Used for AES-256-GCM encrypt/decrypt.
    created_at : float
        UNIX timestamp at session creation.
    last_sequence : int
        Sequence number of the last accepted telemetry packet.
        Initialized to -1 (no packets received yet).
    """

    def __init__(
        self,
        session_id: str,
        shared_secret: bytes,
        aes_key: bytes,
    ) -> None:
        self.session_id = session_id
        self.shared_secret = shared_secret
        self.aes_key = aes_key
        self.created_at = time.time()
        self.last_sequence = -1

    def age_seconds(self) -> float:
        """Elapsed time since session was established."""
        return time.time() - self.created_at

    def is_expired(self, ttl_seconds: float = 600.0) -> bool:
        """Return True if the session has exceeded its TTL."""
        return self.age_seconds() > ttl_seconds

    def __repr__(self) -> str:
        return (
            f"SessionState(id={self.session_id!r}, "
            f"age={self.age_seconds():.1f}s, "
            f"last_seq={self.last_sequence})"
        )
