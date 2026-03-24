"""
tests/test_secure_pipeline.py

End-to-end validation for the secure telemetry pipeline.

This test proves that the major building blocks work together:
1) build a telemetry frame
2) serialize it deterministically
3) encrypt it with AES-GCM
4) sign the encrypted envelope with ML-DSA
5) verify the signature
6) decrypt the ciphertext
7) parse the original frame back out
"""

from ccsds.packet import build_frame, canonical_json_bytes, parse_json_bytes
from crypto.aes_gcm import encrypt, decrypt
from crypto.mldsa_signatures import generate_keypair, sign, verify, b64e, b64d

#from crypto.pq_sign import generate_keypair, sign, verify, b64e, b64d

def test_secure_pipeline_roundtrip():
    # Demo values for the test
    aes_key = b"0123456789ABCDEF0123456789ABCDEF"
    spacecraft_id = "AegisLEO-SAT-1"
    apid = 100

    # Generate a temporary ML-DSA keypair for this unit test
    kp = generate_keypair()

    # Step 1: Build a telemetry frame
    frame = build_frame(
        spacecraft_id=spacecraft_id,
        sequence=42,
        apid=apid,
        payload={
            "temp_c": 12.34,
            "bus_v": 5.01,
            "bus_i": 0.411,
            "state": "NOMINAL",
        },
    )

    # Step 2: Convert frame into canonical bytes
    frame_bytes = canonical_json_bytes(frame)

    # Step 3: Encrypt the frame
    encrypted = encrypt(
        frame_bytes,
        aes_key,
        aad=spacecraft_id.encode("utf-8"),
    )

    # Step 4: Build the encrypted packet core
    packet_core = {
        "spacecraft_id": spacecraft_id,
        "algorithms": {
            "enc": "AES-256-GCM",
            "sig": "ML-DSA-65",
        },
        "nonce": b64e(encrypted["nonce"]),
        "ciphertext": b64e(encrypted["ciphertext"]),
    }

    # Step 5: Sign the packet core
    packet_core_bytes = canonical_json_bytes(packet_core)
    signature = sign(packet_core_bytes, kp.secret_key)

    # Step 6: Verify the signature
    assert verify(packet_core_bytes, signature, kp.public_key) is True

    # Step 7: Decrypt the ciphertext
    plaintext = decrypt(
        b64d(packet_core["nonce"]),
        b64d(packet_core["ciphertext"]),
        aes_key,
        aad=spacecraft_id.encode("utf-8"),
    )

    # Step 8: Parse the original frame
    parsed = parse_json_bytes(plaintext)

    # Final assertions
    assert parsed["spacecraft_id"] == spacecraft_id
    assert parsed["sequence"] == 42
    assert parsed["apid"] == apid
    assert parsed["payload"]["temp_c"] == 12.34
    assert parsed["payload"]["state"] == "NOMINAL"