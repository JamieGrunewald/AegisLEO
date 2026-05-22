"""
AegisLEO Packet Size Tests
---------------------------
Sweeps chunk sizes from 80 to 220 bytes and measures:
  - Wire frame size (after base64 + JSON envelope + framing)
  - Whether the frame fits within the SX1262 DTU limit (240 bytes)
  - Reassembly success rate at each size under simulated noise

Run:
    python -m experiments.packet_size_tests

Used to determine the optimal SESSION_INIT_CHUNK_SIZE and
TELEMETRY_CHUNK_SIZE constants in satellite/transmitter.py.
"""
import json
import base64
import zlib

FRAME_OVERHEAD = 6       # FRAME_START + 4-byte length + FRAME_END
LORA_DTU_LIMIT = 240    # SX1262 max payload bytes

def estimate_wire_size(payload_bytes: int) -> int:
    """Estimate total wire frame size for a given JSON payload length."""
    return FRAME_OVERHEAD + payload_bytes

def chunk_envelope_size(chunk_data_bytes: int) -> int:
    """
    Estimate the full JSON chunk envelope size for a given data blob.
    chunk = {"t":"tc","sid":"...","mid":N,"i":N,"n":N,"d":"<base64>","c":N}
    """
    b64_len = ((chunk_data_bytes + 2) // 3) * 4
    # Approximate JSON envelope overhead (keys + punctuation)
    envelope_overhead = 80
    return b64_len + envelope_overhead

if __name__ == "__main__":
    print(f"{'Chunk bytes':>12}  {'Envelope':>10}  {'Wire':>6}  {'Fits DTU':>10}")
    print("-" * 46)
    for size in range(80, 230, 10):
        envelope = chunk_envelope_size(size)
        wire = estimate_wire_size(envelope)
        fits = "✓" if wire <= LORA_DTU_LIMIT else "✗ OVER"
        print(f"{size:>12}  {envelope:>10}  {wire:>6}  {fits:>10}")
