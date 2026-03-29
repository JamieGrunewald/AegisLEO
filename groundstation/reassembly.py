"""
AegisLEO Chunk Reassembly

Created by: Jamie Grunewald
Date: 2026-03-28
Version: v0.1.0

Purpose
-------
This file handles the problem of putting a large message back together
after it has been split into small pieces (chunks) for transport over LoRa.

Why do we need this?
--------------------
LoRa radio frames have a maximum payload size of 255 bytes.

Our telemetry packets are much larger than that — they contain:
  - ML-DSA-65 signatures (~3,300 bytes)
  - ML-KEM-1024 ciphertext (~1,568 bytes)
  - AES-256-GCM encrypted payload
  - base64 encoding overhead on top of all that

So the transmitter (satellite side) splits the big packet into small
numbered fragments called "chunks" and sends them one at a time.

This module is responsible for:
  1. Accepting incoming chunks as they arrive (possibly out of order)
  2. Keeping track of which chunks we have and which are still missing
  3. Detecting and ignoring duplicate chunks
  4. Detecting and rejecting conflicting chunks (same index, different data)
  5. Reassembling the full message once all chunks have arrived
  6. Expiring stale incomplete messages that never fully arrived

Where does this fit in the bigger picture?
------------------------------------------

  [satellite transmits chunk 0] --> [receiver gets chunk 0] --> ChunkAssembly stores it
  [satellite transmits chunk 1] --> [receiver gets chunk 1] --> ChunkAssembly stores it
  [satellite transmits chunk 2] --> [LOST ON RF LINK]       --> ChunkAssembly notices it's missing
  [satellite transmits chunk 3] --> [receiver gets chunk 3] --> ChunkAssembly stores it
  ...
  [receiver sends NACK: "missing chunk 2"]
  [satellite retransmits chunk 2] --> [receiver gets chunk 2] --> ChunkAssembly now complete!
  [receiver reassembles full packet and processes it]
  [receiver sends ACK]

Key concepts used here
----------------------
dataclass:
    A Python decorator that auto-generates __init__, __repr__, etc.
    We use it so we don't have to write boilerplate constructor code.

dict:
    Python's built-in key-value store. We use it to hold chunk data
    keyed by chunk index. dict[int, str] means: keys are ints (chunk
    index), values are strings (the base64 fragment data).

field(default_factory=...):
    When a dataclass attribute has a mutable default (like a dict or list),
    you CANNOT just write `parts: dict = {}`. Python would share the same
    dict object across ALL instances — a classic Python gotcha.
    Using field(default_factory=dict) tells Python to call dict() fresh
    for each new instance. Same pattern for time.time().

tuple[bool, bool]:
    A pair of booleans. Python functions can return multiple values as a
    tuple. We unpack them at the call site like:
        is_dup, is_conflict = buf.add_part(idx, data)
"""

from __future__ import annotations

# ---------------------------------------------------------------------
# Standard library imports
# ---------------------------------------------------------------------

import base64          # For decoding base64 chunk data back into bytes
import json            # For parsing JSON once a packet is reassembled
import time            # For tracking when chunks arrived (TTL logic)
import zlib            # For decompressing the reassembled payload

# dataclass: lets us define clean data-holding classes without writing
# a lot of __init__ boilerplate.
# field: lets us safely define mutable default values in dataclasses.
from dataclasses import dataclass, field


# =============================================================================
# SECTION 1: THE CHUNK ASSEMBLY BUFFER
# =============================================================================
#
# A ChunkAssembly object represents ONE in-flight logical message.
# It holds all the pieces we have received so far, and knows how many
# pieces the full message is supposed to have.
#
# Think of it like a jigsaw puzzle box:
#   - total_chunks  = how many puzzle pieces exist in total
#   - parts         = the pieces we have collected so far
#   - created_at    = when we started collecting
#   - updated_at    = when we last received a new piece
#
# The receiver maintains a dict of these, one per message in flight.
# =============================================================================

@dataclass
class ChunkAssembly:
    """
    Holds the incoming chunks for one logical message until it is complete.

    Attributes
    ----------
    total_chunks : int
        How many chunks the sender says the full message has.
        This comes from the "n" field in each transport packet.
        Example: if the transmitter says n=36, we need chunks 0 through 35.

    created_at : float
        Unix timestamp when this assembly buffer was first created.
        Used to calculate how old a stale message is.
        default_factory=time.time means "call time.time() when creating
        a new instance" — so each instance gets its own timestamp.

    updated_at : float
        Unix timestamp when we last received any chunk for this message.
        We use this for TTL (time-to-live) expiry: if no chunk arrives
        for N seconds, we give up on the message and clean it up.

    parts : dict[int, str]
        The chunk data we have received so far.
        Key   = chunk index (0-based integer, e.g. 0, 1, 2, ...)
        Value = the base64 string data fragment for that chunk index

        Example after receiving chunks 0, 1, and 3 (chunk 2 is still missing):
            {
                0: "SGVsbG8gV29ybGQ...",
                1: "dGhpcyBpcyBjaHVu...",
                3: "bmsgMyBkYXRh..."
            }
    """

    total_chunks: int

    # time.time() returns the current Unix timestamp as a float.
    # We use default_factory so each instance gets its OWN timestamp,
    # not a shared one computed at class definition time.
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    # dict() creates a fresh empty dictionary for each instance.
    # dict[int, str] is just a type hint — chunk_index -> base64_fragment
    parts: dict[int, str] = field(default_factory=dict)


    # -------------------------------------------------------------------------
    # METHOD: add_part
    # -------------------------------------------------------------------------
    # This is called every time a new chunk arrives for this message.
    # It handles three cases:
    #   1. Brand new chunk  -> store it, return (False, False)
    #   2. Exact duplicate  -> ignore it, return (True, False)
    #   3. Conflicting dup  -> same index but DIFFERENT data -> return (False, True)
    # -------------------------------------------------------------------------

    def add_part(self, idx: int, data: str) -> tuple[bool, bool]:
        """
        Try to add a chunk fragment to this assembly buffer.

        Parameters
        ----------
        idx : int
            The chunk index. Must be in range [0, total_chunks - 1].
            This comes from the "i" field in the transport packet.

        data : str
            The base64-encoded string fragment for this chunk.
            This comes from the "d" field in the transport packet.

        Returns
        -------
        tuple[bool, bool]
            (is_accepted_duplicate, is_conflicting_duplicate)

            Case 1 - New chunk:
                (False, False) -> stored successfully

            Case 2 - Exact duplicate (same data we already have):
                (True, False)  -> already have it, safely ignored

            Case 3 - Conflicting duplicate (different data for same index):
                (False, True)  -> something is wrong, caller should reset

        Why do we care about conflicting duplicates?
        --------------------------------------------
        On a noisy radio link, bit errors could corrupt a chunk so that
        the CRC check passes (unlikely but possible with CRC32).
        If we already have chunk 5 with content "AAAA..." and we receive
        another chunk 5 with content "ZZZZ...", that's a red flag.
        We return the conflict flag so the caller can decide to reset
        the entire assembly buffer and start over.
        """

        # Look up whether we already have a chunk at this index.
        # .get() returns None if the key doesn't exist (no KeyError).
        existing = self.parts.get(idx)

        # --- Case 2: We already have a chunk at this index ---
        if existing is not None:

            # Sub-case 2a: Exact duplicate — same data we already stored.
            # This is normal on lossy links where the sender retransmits
            # chunks we already have. Safe to ignore.
            if existing == data:
                self.updated_at = time.time()   # Still counts as activity
                return True, False              # (is_dup=True, is_conflict=False)

            # Sub-case 2b: CONFLICTING duplicate — same index, different data.
            # This should not happen under normal operation.
            # We signal the conflict to the caller without modifying state.
            return False, True                  # (is_dup=False, is_conflict=True)

        # --- Case 1: Brand new chunk we haven't seen before ---
        # Store it in our parts dictionary.
        self.parts[idx] = data

        # Update the "last activity" timestamp so TTL logic works correctly.
        self.updated_at = time.time()

        return False, False                     # (is_dup=False, is_conflict=False)


    # -------------------------------------------------------------------------
    # METHOD: is_complete
    # -------------------------------------------------------------------------
    # Simple check: do we have ALL the chunks?
    #
    # len(self.parts) = how many chunks we have collected
    # self.total_chunks = how many chunks the full message has
    #
    # When these are equal, we have everything and can reassemble.
    # -------------------------------------------------------------------------

    def is_complete(self) -> bool:
        """
        Return True if we have received every chunk for this message.

        How it works:
            If total_chunks is 36 and we have 36 entries in parts,
            we have everything. (We validated idx range on intake so
            there can't be out-of-range keys sneaking in.)
        """
        return len(self.parts) == self.total_chunks


    # -------------------------------------------------------------------------
    # METHOD: missing_indexes
    # -------------------------------------------------------------------------
    # Produces the list of chunk indexes we are still waiting for.
    # This is sent back to the satellite in a NACK packet so it knows
    # exactly which chunks to retransmit.
    # -------------------------------------------------------------------------

    def missing_indexes(self) -> list[int]:
        """
        Return a list of chunk indexes that have not yet arrived.

        How it works:
            range(self.total_chunks) produces [0, 1, 2, ..., total_chunks-1]
            We keep only the ones NOT present in self.parts.

        Example:
            total_chunks = 5
            parts has keys {0, 1, 3}
            missing_indexes() returns [2, 4]

        This list goes directly into the NACK packet's "m" field,
        which tells the satellite exactly which chunks to resend.
        """
        return [i for i in range(self.total_chunks) if i not in self.parts]


    # -------------------------------------------------------------------------
    # METHOD: assemble
    # -------------------------------------------------------------------------
    # Once is_complete() returns True, this puts all the pieces together
    # in the correct order and returns the full base64 string.
    #
    # Why sort by index?
    # Because chunks can arrive OUT OF ORDER over a lossy radio link.
    # chunk 3 might arrive before chunk 1. We must reassemble in
    # index order (0, 1, 2, 3...) regardless of arrival order.
    # -------------------------------------------------------------------------

    def assemble(self) -> str:
        """
        Concatenate all chunk fragments in index order into one string.

        Returns
        -------
        str
            The complete base64-encoded payload string, ready to be
            passed to b64text_to_packet() for decoding.

        IMPORTANT: Only call this after is_complete() returns True.
        Calling it with missing chunks will produce a corrupt result
        because the missing indexes will simply be absent from the join.
        """

        # range(self.total_chunks) gives us the indexes in order: 0, 1, 2...
        # self.parts[i] fetches the stored fragment for each index.
        # "".join(...) concatenates them all into one big string with no separator.
        return "".join(self.parts[i] for i in range(self.total_chunks))


# =============================================================================
# SECTION 2: THE REASSEMBLY STORE
# =============================================================================
#
# The ReassemblyStore manages ALL in-flight messages at once.
# It is a thin wrapper around a dict of ChunkAssembly objects.
#
# Why wrap it in a class instead of using a raw dict?
# -----------------------------------------------------
# Because the cleanup (TTL expiry), key construction, and stats tracking
# logic all belong here logically. If we left it as a raw dict in receiver.py,
# that file would get cluttered with reassembly logic mixed into its
# main loop. Separation of concerns.
#
# The key for each in-flight message is a tuple:
#   (chunk_type, session_id, message_id)
#
#   chunk_type : "si" (session-init) or "tc" (telemetry chunk)
#   session_id : hex string identifying the crypto session
#   message_id : integer sequence number, or None for session-init
#
# Using a tuple as a dict key works because tuples are hashable in Python.
# =============================================================================

# TTL constants — how long we wait before giving up on an incomplete message.
#
# Session-init gets more time because it's large (31 chunks) and we really
# need it to succeed before any telemetry can flow.
#
# Telemetry gets less time because packets are smaller and we'd rather
# move on than hold stale state forever.

SESSION_INIT_TTL_SECONDS = 25.0
TELEMETRY_TTL_SECONDS    = 30.0

# The receiver's NACK packet can only list this many missing chunk indexes.
# If more are missing, we send the first N and wait for the next round.
MAX_MISSING_PER_NACK = 36


# Type alias for the reassembly key.
# Using a type alias makes the code easier to read — instead of writing
# tuple[str, str, int | None] everywhere, we write ReassemblyKey.
#
# str  = chunk_type  ("si" or "tc")
# str  = session_id  (hex string)
# int | None = message_id (sequence number, or None for session-init)
ReassemblyKey = tuple[str, str, int | None]


class ReassemblyFactory:
    """
    Manages all in-flight chunk reassembly buffers.

    One instance of this lives in receiver.py and handles every
    incoming message across all active sessions simultaneously.

    Internal storage
    ----------------
    self._buffers : dict[ReassemblyKey, ChunkAssembly]

        Key   = (chunk_type, session_id, message_id)
        Value = ChunkAssembly tracking the chunks for that message

    Example state when two messages are in flight:

        {
            ("tc", "d985e3a60842a92c", 42): ChunkAssembly(total=36, have=31),
            ("tc", "d985e3a60842a92c", 43): ChunkAssembly(total=36, have=12),
        }
    """

    def __init__(self) -> None:
        # The main storage dict. Starts empty; grows as messages arrive.
        self._buffers: dict[ReassemblyKey, ChunkAssembly] = {}

        # Counters for the stats line printed every few seconds.
        # We track these here so receiver.py doesn't need to maintain them.
        self.stats_chunks_total     = 0
        self.stats_chunks_accepted  = 0
        self.stats_chunks_duplicate = 0
        self.stats_chunks_conflict  = 0
        self.stats_chunks_crc_fail  = 0
        self.stats_reassembled      = 0


    # -------------------------------------------------------------------------
    # HELPER: _make_key
    # -------------------------------------------------------------------------
    # Builds the tuple used as the dict key for a given message.
    # Keeping this in one place means we can never accidentally build
    # the key differently in different parts of the code.
    # -------------------------------------------------------------------------

    @staticmethod
    def _make_key(chunk_type: str, session_id: str, message_id: int | None) -> ReassemblyKey:
        """
        Build the lookup key for a given message.

        Parameters
        ----------
        chunk_type : str
            "si" for session-init, "tc" for telemetry chunk.
        session_id : str
            The session identifier string from the transport packet.
        message_id : int | None
            The message sequence number, or None for session-init.

        Returns
        -------
        ReassemblyKey
            A 3-tuple suitable for use as a dict key.
        """
        return (chunk_type, session_id, message_id)


    # -------------------------------------------------------------------------
    # HELPER: _get_ttl
    # -------------------------------------------------------------------------
    # Returns how long (in seconds) we should wait before giving up on
    # a message that has stopped making progress.
    # -------------------------------------------------------------------------

    @staticmethod
    def _get_ttl(message_id: int | None) -> float:
        """
        Return the TTL for this message type.

        Session-init (message_id is None) gets more time because it's
        large and critical — without it no telemetry can be processed.

        Telemetry gets a shorter TTL because we prefer to garbage-collect
        old incomplete messages rather than let the buffer grow forever.
        """
        return SESSION_INIT_TTL_SECONDS if message_id is None else TELEMETRY_TTL_SECONDS


    # -------------------------------------------------------------------------
    # METHOD: add_chunk
    # -------------------------------------------------------------------------
    # This is the main entry point called by receiver.py for every
    # incoming transport packet that carries chunk data.
    #
    # It does NOT decode or process the reassembled packet — that stays
    # in receiver.py. This method only manages the raw chunk storage.
    # -------------------------------------------------------------------------

    def add_chunk(
        self,
        chunk_type: str,
        session_id: str,
        message_id: int | None,
        chunk_index: int,
        chunk_total: int,
        data_fragment: str,
        crc_expected: int,
    ) -> tuple[bool, list[int] | None]:
        """
        Accept one incoming chunk and attempt reassembly.

        Parameters
        ----------
        chunk_type : str
            "si" or "tc" — identifies the logical packet type.
        session_id : str
            Session identifier from the transport packet "sid" field.
        message_id : int | None
            Sequence number from "mid", or None for session-init.
        chunk_index : int
            Zero-based index of this chunk (the "i" field).
        chunk_total : int
            Total number of chunks in this message (the "n" field).
        data_fragment : str
            The base64 string content of this chunk (the "d" field).
        crc_expected : int
            CRC32 checksum of data_fragment as sent by the transmitter.
            We verify this before storing to catch RF bit errors.

        Returns
        -------
        tuple[bool, list[int] | None]

            Case 1 - Message is now complete:
                (True, None)
                Caller should call get_assembled() to retrieve the payload.

            Case 2 - Message is incomplete, missing indexes known:
                (False, [2, 5, 7, ...])
                Caller may send a NACK with these indexes.

            Case 3 - Chunk rejected (CRC fail, conflict, etc.):
                (False, None)
                Caller should log and move on; no NACK needed yet.
        """

        # Run cleanup first so stale buffers don't accumulate indefinitely.
        # We do this on every chunk arrival — it's cheap and keeps memory tidy.
        self.flush_stale()

        self.stats_chunks_total += 1

        # --- CRC verification ---
        # CRC32 is a checksum algorithm. The transmitter computes it over
        # the data_fragment string and includes the result in the packet.
        # We recompute it here and compare. If they don't match, a bit
        # was flipped somewhere on the radio link and we discard the chunk.
        #
        # zlib.crc32() can return a signed integer on some platforms.
        # The & 0xFFFFFFFF masks it to an unsigned 32-bit value to match
        # what the transmitter sends.
        import zlib
        actual_crc = zlib.crc32(data_fragment.encode("utf-8")) & 0xFFFFFFFF

        if actual_crc != crc_expected:
            self.stats_chunks_crc_fail += 1
            # Return None for missing list — we don't know what's missing yet,
            # and the caller will eventually trigger a NACK via TTL cleanup.
            return False, None

        # --- Look up or create the assembly buffer for this message ---
        key = self._make_key(chunk_type, session_id, message_id)

        if key not in self._buffers:
            # First chunk we've seen for this message — create a new buffer.
            self._buffers[key] = ChunkAssembly(total_chunks=chunk_total)

        buf = self._buffers[key]

        # --- Sanity check: total chunk count must be consistent ---
        # If chunk 0 said n=36 but chunk 5 says n=40, something is wrong.
        # We reset the buffer to avoid assembling a corrupted message.
        if buf.total_chunks != chunk_total:
            del self._buffers[key]
            return False, None

        # --- Try to add the chunk ---
        is_dup, is_conflict = buf.add_part(chunk_index, data_fragment)

        if is_conflict:
            # Same index, different data — reset the whole buffer.
            self.stats_chunks_conflict += 1
            del self._buffers[key]
            return False, None

        if is_dup:
            # Already have this exact chunk. Safe to ignore.
            self.stats_chunks_duplicate += 1
            # Return the current missing list so the caller knows the state.
            missing = buf.missing_indexes()
            return False, missing[:MAX_MISSING_PER_NACK] if missing else None

        # New chunk successfully stored.
        self.stats_chunks_accepted += 1

        # --- Check if the message is now complete ---
        if buf.is_complete():
            # All chunks have arrived — signal completion.
            # We do NOT delete the buffer here; get_assembled() does that.
            return True, None

        # Not complete yet. Return the list of missing chunks so the caller
        # can decide whether to send a NACK.
        missing = buf.missing_indexes()
        return False, missing[:MAX_MISSING_PER_NACK]


    # -------------------------------------------------------------------------
    # METHOD: get_assembled
    # -------------------------------------------------------------------------
    # Called after add_chunk returns (True, None) to retrieve the
    # completed payload and remove the buffer from memory.
    # -------------------------------------------------------------------------

    def get_assembled(
        self,
        chunk_type: str,
        session_id: str,
        message_id: int | None,
    ) -> str | None:
        """
        Retrieve the fully assembled base64 payload and clean up.

        Parameters
        ----------
        chunk_type, session_id, message_id : same as add_chunk

        Returns
        -------
        str | None
            The assembled base64 string, or None if the buffer doesn't
            exist or isn't complete (shouldn't happen in normal flow).
        """
        key = self._make_key(chunk_type, session_id, message_id)
        buf = self._buffers.get(key)

        if buf is None or not buf.is_complete():
            return None

        # Assemble the full payload string from the ordered chunks.
        assembled = buf.assemble()

        # Remove the buffer — we're done with this message.
        del self._buffers[key]

        self.stats_reassembled += 1

        return assembled


    # -------------------------------------------------------------------------
    # METHOD: flush_stale
    # -------------------------------------------------------------------------
    # Scans all in-flight buffers and removes any that have exceeded their
    # TTL without completing. This prevents memory from growing without
    # bound over a long session.
    #
    # "Stale" means: incomplete AND last updated more than TTL seconds ago.
    # Complete buffers are removed by get_assembled(), not here.
    # -------------------------------------------------------------------------

    def flush_stale(self) -> list[tuple[str, int | None, list[int]]]:
        """
        Remove stale incomplete buffers and return their missing chunk lists.

        Returns
        -------
        list of (session_id, message_id, missing_indexes)
            One entry per expired buffer. The caller (receiver.py) can use
            these to send NACK packets before the buffer is gone.

        Why return the missing list?
        ----------------------------
        receiver.py needs to send a NACK so the satellite knows to retry.
        If we silently delete the buffer without telling the satellite,
        the message is just lost with no recovery attempt.
        """
        now = time.time()

        # We collect stale keys first, then delete them.
        # You CANNOT delete from a dict while iterating over it in Python —
        # that raises a RuntimeError. Collect first, delete after.
        stale_keys: list[ReassemblyKey] = []

        for key, buf in self._buffers.items():
            _, _, message_id = key
            ttl = self._get_ttl(message_id)

            # updated_at is refreshed every time a new chunk arrives.
            # If it's been TTL seconds since the last chunk, give up.
            age = now - buf.updated_at

            if age > ttl and not buf.is_complete():
                stale_keys.append(key)

        # Build the return list BEFORE deleting so we can read the buffers.
        expired_info: list[tuple[str, int | None, list[int]]] = []

        for key in stale_keys:
            chunk_type, session_id, message_id = key
            buf = self._buffers[key]
            missing = buf.missing_indexes()

            # Trim to the NACK limit so we don't send a 36-item NACK.
            trimmed_missing = missing[:MAX_MISSING_PER_NACK]

            expired_info.append((session_id, message_id, trimmed_missing))

            # Now safe to delete — we're not inside the iteration anymore.
            del self._buffers[key]

        return expired_info


    # -------------------------------------------------------------------------
    # METHOD: debug_state
    # -------------------------------------------------------------------------
    # Returns a snapshot of all in-flight buffers for logging.
    # Useful for the [GROUND][STATS] log line.
    # -------------------------------------------------------------------------

    def debug_state(self) -> dict:
        """
        Return a summary of current reassembly state for logging/debugging.
        """
        return {
            "in_flight": len(self._buffers),
            "chunks_total":     self.stats_chunks_total,
            "chunks_accepted":  self.stats_chunks_accepted,
            "chunks_duplicate": self.stats_chunks_duplicate,
            "chunks_conflict":  self.stats_chunks_conflict,
            "chunks_crc_fail":  self.stats_chunks_crc_fail,
            "reassembled":      self.stats_reassembled,
        }


# =============================================================================
# SECTION 3: LOGICAL PACKET DECODING
# =============================================================================
#
# Once a message is fully reassembled, the result is a base64 string.
# This function reverses the encoding pipeline the transmitter applied:
#
#   Transmitter side (encoding):
#       1. dict  -> compact JSON string   (json.dumps)
#       2. str   -> bytes                 (.encode("utf-8"))
#       3. bytes -> compressed bytes      (zlib.compress)
#       4. bytes -> base64 string         (base64.b64encode)
#
#   Receiver side (decoding, this function):
#       1. base64 string -> bytes         (base64.b64decode)
#       2. bytes -> decompressed bytes    (zlib.decompress)
#       3. bytes -> dict                  (json.loads)
#
# Why compress before encoding?
# Because zlib compression shrinks the JSON significantly (often 30-50%),
# which means fewer chunks, fewer transmissions, and faster delivery
# over the slow LoRa radio link.
# =============================================================================

def decode_assembled_payload(text: str) -> dict:
    """
    Decode a fully assembled base64 payload back into a Python dict.

    This reverses the transmitter's encode pipeline:
        base64 -> zlib decompress -> JSON parse

    Parameters
    ----------
    text : str
        The assembled base64 string from ReassemblyFactory.get_assembled().

    Returns
    -------
    dict
        The original logical packet as a Python dictionary.

    Raises
    ------
    Exception
        Any decode/decompress/json error propagates to the caller.
        receiver.py wraps this in try/except and sends a NACK on failure.

    Example
    -------
    If the transmitter sent a session_init packet, this returns something like:
        {
            "type": "session_init",
            "spacecraft_id": "AegisLEO-SAT-1",
            "session_id": "d985e3a60842a92c",
            "kem_ciphertext": "<base64 of ML-KEM-1024 ciphertext>",
            "signature": "<base64 of ML-DSA-65 signature>"
        }
    """

    # Step 1: base64 decode
    # validate=True rejects any characters that aren't valid base64,
    # catching corruption early before we try to decompress.
    compressed = base64.b64decode(text.encode("utf-8"), validate=True)

    # Step 2: zlib decompress
    # This will raise zlib.error if the data was corrupted.
    raw = zlib.decompress(compressed)

    # Step 3: JSON parse
    # raw is UTF-8 bytes. .decode() turns it into a string, then
    # json.loads() turns it into a Python dict.
    return json.loads(raw.decode("utf-8"))