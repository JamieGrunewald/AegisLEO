"""
AegisLEO — Chunk Reassembly (v2.0 Refactor Target)
====================================================

Created by: Jamie Grunewald
Date: 2026-03-26
Version: v0.1.0 (stub)

Purpose
-------
Planned extraction of the chunk reassembly logic currently embedded in
groundstation/receiver.py into a standalone, testable module.

In the current pipeline, the receiver manages chunk collection, timeout
tracking, NACK generation, and session buffer cleanup all within a single
large receive loop. This module is the planned home for that logic once
it is refactored into a clean ReassemblyFactory class.

Current state
-------------
The reassembly logic lives inline in groundstation/receiver.py. This file
is a stub reserved for the v2.0 refactor. Once implemented, receiver.py
will import ReassemblyFactory from here, making the reassembly logic
independently testable.

Planned interface
-----------------
    factory = ReassemblyFactory(ttl_telemetry=8.0, ttl_session_init=600.0)
    factory.ingest(chunk)           # add a chunk to the appropriate buffer
    packet = factory.try_assemble() # returns complete packet or None
    factory.expire_stale()          # evict timed-out incomplete sessions
    nacks = factory.pending_nacks() # list of (session_id, missing_indices)

See also
--------
- groundstation/receiver.py  — current inline reassembly implementation
- common/chunking.py         — chunk envelope format
- docs/protocol_spec.md      — chunk protocol specification
"""

# TODO: extract ReassemblyFactory from groundstation/receiver.py
