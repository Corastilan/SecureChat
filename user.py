from dataclasses import dataclass, field
from typing import Dict, Tuple
from key_management import KeyManager
from utils import Utils

"""
1. Create: to create a user and generate a key pair for them
2. encrypt_for_peer: Construct AAD using a random nonce, sender/receiver data and encrypt the payload
3. decrypt_from_peer: Reconstruct AAD and decrypt the payload
"""

@dataclass
class User:
    username: str
    sid: str
    x_priv: any
    x_pub_bytes: bytes
    p2p_keys: Dict[str, bytes] = field(default_factory=dict)
    p2p_counters: Dict[str, int] = field(default_factory=dict)

    @staticmethod
    def create(username: str, sid: str) -> "User":
        priv, pub_bytes = KeyManager.generate_key_pair()
        return User(
            username=username,
            sid=sid,
            x_priv=priv,
            x_pub_bytes=pub_bytes
        )

    def encrypt_for_peer(self, peer_username: str, plaintext: str) -> Tuple[int, bytes, bytes]:
        key = self.p2p_keys.get(peer_username)
        if not key:
            raise ValueError(f"No P2P session with {peer_username}")
        
        count = self.p2p_counters.get(peer_username, 0)
        aad = f"p2p:{self.username}:{peer_username}:c:{count}".encode("utf-8")
        nonce, ct = Utils.encrypt_aes_gcm(key, plaintext, aad)
        
        self.p2p_counters[peer_username] = count + 1
        return count, nonce, ct

    def decrypt_from_peer(self, peer_username: str, count: int, nonce: bytes, ciphertext: bytes) -> str:
        key = self.p2p_keys.get(peer_username)
        if not key:
            raise ValueError(f"No P2P session with {peer_username}")

        aad = f"p2p:{peer_username}:{self.username}:c:{count}".encode("utf-8")
        return Utils.decrypt_aes_gcm(key, nonce, ciphertext, aad)
