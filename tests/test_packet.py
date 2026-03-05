"""
tests/test_packet.py

Unit tests help us prove two key properties:
1) Packet serialization/deserialization works (roundtrip)
2) CRC catches tampering/corruption

Later, we will add tests for AES-GCM authentication failures too.
"""

from common.packet import Packet, encode_telemetry_json, decode_telemetry_json, now_ms


def test_packet_roundtrip():
    payload = encode_telemetry_json({"hello": "world", "n": 1})
    pkt = Packet(apid=1, seq=7, ts_ms=now_ms(), flags=0, payload=payload)

    raw = pkt.to_bytes()
    pkt2 = Packet.from_bytes(raw)

    assert pkt2.apid == pkt.apid
    assert pkt2.seq == pkt.seq
    assert decode_telemetry_json(pkt2.payload) == {"hello": "world", "n": 1}


def test_crc_catches_tamper():
    payload = encode_telemetry_json({"x": 123})
    pkt = Packet(apid=2, seq=1, ts_ms=now_ms(), flags=0, payload=payload)

    raw = bytearray(pkt.to_bytes())

    # Flip one bit in the payload, simulating a tamper/corruption event.
    raw[-1] ^= 0x01

    try:
        Packet.from_bytes(bytes(raw))
        assert False, "expected CRC error, but parsing succeeded"
    except ValueError as e:
        assert "crc mismatch" in str(e)
