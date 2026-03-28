import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

"""
Utils to encrypt and decrypt at the base level. 
Common utils for both users and groups.
Derive a versioned (epoch-based) group key from a master seed.
Password hasher class to help with login.
Double-Lock Security:
1. Hash with Scrypt + Random Salt.
2. Encrypt the Hash itself with a Server Master Key.
"""

class Utils:
    @staticmethod
    def random_key_32() -> bytes:
        return os.urandom(32)

    @staticmethod
    def derive_aes_key(shared_secret: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"apcry-secure-messaging",
            info=b"p2p-session-key",
        ).derive(shared_secret)

    @staticmethod
    def derive_group_epoch_key(master_seed: bytes, group_id: str, epoch: int) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=group_id.encode('utf-8'),
            info=f"epoch-{epoch}".encode('utf-8'),
        ).derive(master_seed)

    @staticmethod
    def encrypt_aes_gcm(key: bytes, plaintext: str, aad: bytes) -> tuple[bytes, bytes]:
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)
        return nonce, ciphertext

    @staticmethod
    def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> str:
        pt = AESGCM(key).decrypt(nonce, ciphertext, aad)
        return pt.decode("utf-8")

class PasswordHasher:
    _MASTER_PEPPER = b"apcry-master-pepper-key-32-bytes"

    @staticmethod
    def hash_password(password: str) -> str:
        salt = os.urandom(16)
        pwd_hash = hashlib.scrypt(
            password.encode('utf-8'), salt=salt, n=16384, r=8, p=1
        )
        
        nonce, encrypted_hash = Utils.encrypt_aes_gcm(
            PasswordHasher._MASTER_PEPPER, 
            pwd_hash.hex(), 
            b"password-envelope-context"
        )
        
        return f"{salt.hex()}:{nonce.hex()}:{encrypted_hash.hex()}"

    @staticmethod
    def verify_password(stored_data: str, password: str) -> bool:
        if not stored_data or stored_data.count(":") != 2:
            return False
        
        try:
            salt_hex, nonce_hex, ct_hex = stored_data.split(":")
            salt = bytes.fromhex(salt_hex)
            nonce = bytes.fromhex(nonce_hex)
            ciphertext = bytes.fromhex(ct_hex)
            
            expected_hash_hex = Utils.decrypt_aes_gcm(
                PasswordHasher._MASTER_PEPPER, 
                nonce, 
                ciphertext, 
                b"password-envelope-context"
            )

            actual_hash = hashlib.scrypt(
                password.encode('utf-8'), salt=salt, n=16384, r=8, p=1
            )
            
            return actual_hash.hex() == expected_hash_hex
        except Exception:
            return False
