import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

class SecureStreamLayer:
    def __init__(self, key, sender_id):
        self.aesgcm = AESGCM(key)
        self.sender_id = sender_id.encode()
        self.last_received_counter = -1

    def encrypt(self, plaintext, counter):
        nonce = os.urandom(12)
        associated_data = self.sender_id + counter.to_bytes(4, 'big')
        ciphertext = self.aesgcm.encrypt(nonce, plaintext.encode(), associated_data)
        return {"nonce": nonce.hex(), "counter": counter, "ciphertext": ciphertext.hex()}

    def decrypt(self, packet):
        nonce = bytes.fromhex(packet["nonce"])
        counter = packet["counter"]
        ciphertext = bytes.fromhex(packet["ciphertext"])
        associated_data = self.sender_id + counter.to_bytes(4, 'big')

        if counter <= self.last_received_counter:
            raise Exception(f"REPLAY ATTACK: Counter {counter} is stale.")

        # This line triggers the 'Security Alert' if keys don't match
        decrypted_data = self.aesgcm.decrypt(nonce, ciphertext, associated_data)
        self.last_received_counter = counter
        return decrypted_data.decode()

class KeyExchange:
    @staticmethod
    def get_params():
        return dh.generate_parameters(generator=2, key_size=2048)

    def __init__(self, parameters):
        self.private_key = parameters.generate_private_key()
        self.public_key = self.private_key.public_key()

    def get_public_bytes(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def derive_static_key(self, public_key_bytes):
        """
        Derives a deterministic key from a public key.
        In a broadcast model, all authorized parties derive the same
        session key from the Producer's public identity.
        """
        # We use the public key as the source of entropy for the session key
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"nyu-salt", # Fixed salt for session sync
            info=b"nyu-vapt-stream-project",
        ).derive(public_key_bytes)