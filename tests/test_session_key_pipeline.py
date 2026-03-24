from ccsds.frame import build_frame, canonical_json_bytes, parse_json_bytes
from crypto.aes_gcm import encrypt, decrypt
from crypto.key_manager import KeyManager


def test_session_key_encrypt_decrypt_roundtrip():
    km = KeyManager()

    receiver = km.create_receiver_bootstrap()
    initiator = km.create_initiator_session(receiver.public_key)
    responder = km.create_receiver_session(
        kem_ciphertext=initiator.kem_ciphertext,
        receiver_private_key=receiver.private_key,
        session_id=initiator.session.session_id,
    )

    assert initiator.session.aes_key == responder.aes_key

    frame = build_frame(
        spacecraft_id="AegisLEO-SAT-1",
        sequence=1,
        apid=100,
        payload={
            "temp_c": 12.3,
            "bus_v": 5.01,
            "bus_i": 0.44,
            "state": "NOMINAL",
        },
    )

    frame_bytes = canonical_json_bytes(frame)

    encrypted = encrypt(
        frame_bytes,
        initiator.session.aes_key,
        aad=b"AegisLEO-SAT-1",
    )

    plaintext = decrypt(
        encrypted["nonce"],
        encrypted["ciphertext"],
        responder.aes_key,
        aad=b"AegisLEO-SAT-1",
    )

    recovered = parse_json_bytes(plaintext)
    assert recovered == frame