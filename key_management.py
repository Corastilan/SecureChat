from cryptography.hazmat.primitives.asymmetric import x25519
from utils import Utils

"""
Key management class to generate key pair for a user, and to compute symmetric key for a P2P chat.
"""

class KeyManager:
    @staticmethod
    def generate_key_pair():
        priv = x25519.X25519PrivateKey.generate()
        pub = priv.public_key()
        return priv, pub.public_bytes_raw()

    @staticmethod
    def compute_p2p_key(my_priv, peer_pub_bytes: bytes) -> bytes:
        peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
        shared_secret = my_priv.exchange(peer_pub)
        return Utils.derive_aes_key(shared_secret)
