"""
tests/test_packet.py

Unit tests help us prove two key properties:
1) Packet serialization/deserialization works (roundtrip)
2) CRC catches tampering/corruption

Later, we will add tests for AES-GCM authentication failures too.
"""

# from common.packet import Packet, encode_telemetry_json, decode_telemetry_json, now_ms
from ccsds.packet import build_frame, canonical_json_bytes, parse_json_bytes


def test_build_frame_has_expected_fields():
    frame = build_frame(
        spacecraft_id="AegisLEO-SAT-1",
        sequence=7,
        apid=100,
        payload={"temp_c": 12.3, "bus_v": 5.01},
    )

    assert frame["version"] == 1
    assert frame["spacecraft_id"] == "AegisLEO-SAT-1"
    assert frame["sequence"] == 7
    assert frame["apid"] == 100
    assert "timestamp" in frame
    assert frame["payload"]["temp_c"] == 12.3


def test_canonical_json_roundtrip():
    frame = build_frame(
        spacecraft_id="AegisLEO-SAT-1",
        sequence=8,
        apid=100,
        payload={"temp_c": 13.4},
    )

    raw = canonical_json_bytes(frame)
    parsed = parse_json_bytes(raw)

    assert parsed == frame