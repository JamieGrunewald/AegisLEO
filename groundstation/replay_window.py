"""
AegisLEO Replay Window

Created by: Jamie Grunewald
Date: 2026-03-23
Version: v0.1.0

Purpose
-------
Provide replay protection for inbound telemetry frames by tracking sequence
numbers inside a sliding acceptance window.

Why this exists
---------------
AES-GCM protects integrity and authenticity of a packet, but it does NOT by
itself prevent a previously valid packet from being captured and replayed later.

This module helps the ground station decide whether an authenticated packet is:
- new and acceptable
- slightly out of order but still acceptable
- a duplicate replay
- too old and therefore rejected

Design
------
- Maintain the highest accepted sequence number seen so far
- Maintain a bitmap of packets seen within the recent window
- Accept:
    * strictly newer packets
    * out-of-order packets that are still inside the window and not duplicates
- Reject:
    * duplicates already seen in the window
    * packets older than the left edge of the window

Notes
-----
- This version assumes sequence numbers are non-negative integers.
- This first implementation does not yet handle sequence rollover.
- For AegisLEO Part 3, that is acceptable and keeps the logic readable.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ReplayDecision:
    """
    Result of evaluating a sequence number against the replay window.
    """

    accepted: bool
    reason: str


class ReplayWindow:
    """
    Sliding replay-protection window using a bitmask.

    Parameters
    ----------
    window_size : int
        Number of recent sequence values to remember.
        Common values are 32, 64, or 128.

    Behavior
    --------
    Let `max_seq` be the highest accepted sequence number so far.

    The active window is roughly:
        [max_seq - window_size + 1, max_seq]

    Within that region:
    - unseen sequence numbers are accepted
    - already-seen sequence numbers are rejected as duplicates

    Anything less than the left edge of the window is rejected as too old.
    Anything greater than max_seq extends the window forward.
    """

    def __init__(self, window_size: int = 64) -> None:
        if window_size <= 0:
            raise ValueError("window_size must be greater than zero")

        self.window_size = window_size
        self.max_seq = -1

        # Bit i represents whether sequence (max_seq - i) has been seen.
        # Bit 0 => max_seq
        # Bit 1 => max_seq - 1
        # Bit 2 => max_seq - 2
        self._seen_mask = 0

    def check(self, seq: int) -> ReplayDecision:
        """
        Evaluate a sequence number without changing state.
        """
        if seq < 0:
            return ReplayDecision(False, "negative_sequence")

        if self.max_seq == -1:
            return ReplayDecision(True, "first_packet")

        if seq > self.max_seq:
            return ReplayDecision(True, "new_high")

        delta = self.max_seq - seq

        if delta >= self.window_size:
            return ReplayDecision(False, "too_old")

        bit = 1 << delta
        if self._seen_mask & bit:
            return ReplayDecision(False, "duplicate")

        return ReplayDecision(True, "in_window_new")

    def accept(self, seq: int) -> bool:
        """
        Evaluate and, if valid, record the sequence number.

        Returns
        -------
        bool
            True if accepted, False if rejected.
        """
        decision = self.check(seq)
        if not decision.accepted:
            return False

        self.record(seq)
        return True

    def record(self, seq: int) -> None:
        """
        Record an accepted sequence number.

        Raises
        ------
        ValueError
            If the sequence is invalid or would not be acceptable.
        """
        if seq < 0:
            raise ValueError("sequence must be non-negative")

        if self.max_seq == -1:
            self.max_seq = seq
            self._seen_mask = 1
            return

        if seq > self.max_seq:
            shift = seq - self.max_seq

            if shift >= self.window_size:
                # Entire old window falls away.
                self._seen_mask = 0
            else:
                self._seen_mask <<= shift
                self._seen_mask &= (1 << self.window_size) - 1

            self.max_seq = seq
            self._seen_mask |= 1
            return

        delta = self.max_seq - seq
        if delta >= self.window_size:
            raise ValueError("sequence is too old to record")

        bit = 1 << delta
        if self._seen_mask & bit:
            raise ValueError("sequence is a duplicate and cannot be recorded")

        self._seen_mask |= bit

    def reset(self) -> None:
        """
        Clear replay-window state.
        """
        self.max_seq = -1
        self._seen_mask = 0

    def window_floor(self) -> int:
        """
        Return the current minimum in-window sequence number.

        Returns -1 if no packets have been accepted yet.
        """
        if self.max_seq == -1:
            return -1
        return max(0, self.max_seq - self.window_size + 1)

    def debug_state(self) -> dict[str, int]:
        """
        Return internal state for debugging/tests.
        """
        return {
            "window_size": self.window_size,
            "max_seq": self.max_seq,
            "seen_mask": self._seen_mask,
            "window_floor": self.window_floor(),
        }