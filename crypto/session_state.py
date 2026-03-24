import time
""""
It should track:

    session_id
    shared_secret (from ML-KEM)
    derived AES key
    creation time
    expiry / rotation
    optional packet counter
"""

class SessionState:
    def __init__(self, session_id: str,shared_secret: bytes,aes_key: bytes):
        self.session_id = session_id
        self.shared_secret = shared_secret
        self.aes_key = aes_key
        self.created_at = time.time()
        self.last_sequence = -1