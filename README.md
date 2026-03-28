# SecureChat: Advanced Multi-Layered Encrypted Messaging

Built with Python, Flask-SocketIO, and cryptography library. We have implemented identity-based key exchange, epoch-based group key updates, and E2E encryption.

## Security Architecture

### 1. Account Security: Envelope Encryption
We don't just hash passwords; we "Double-Lock" them:
- **Primary Layer (Hashing):** Passwords are hashed using Scrypt, a memory-hard algorithm resistant to GPU/ASIC brute-forcing. Each hash uses a unique 16-byte random salt.
- **Secondary Layer (Pepper/Encryption):** The resulting hash is encrypted with a 32-byte server-side Master Pepper using **AES-256-GCM**. 
- **Benefit:** An attacker must compromise *both* the database (for the salts/blobs) and the server's environment (for the Master Pepper) to attempt a crack.

### 2. Peer-to-Peer (P2P) Security: The "Secure Tunnel"
- **Identity Exchange:** Users perform an **X25519 (ECDH)** handshake to establish a shared secret without ever transmitting it.
- **Key Derivation:** We use **HKDF (SHA-256)** with application-specific context to derive a unique symmetric **AES-256** session key.
- **Context Binding:** Every message is bound via **AAD (Additional Authenticated Data)** to the specific `sender`, `receiver`, and a `counter`. This prevents replay and message-reflection attacks.

### 3. Group Security: Epoch-Based Ratcheting
- **Master Seed:** Groups are initialized with a unique `master_seed`. 
- **Epoch Distribution:** The actual encryption key is derived via `HKDF(Master_Seed, Group_ID, Epoch)`.
- **Forward/Backward Secrecy:** Whenever membership changes (Add/Remove), the group increments its **Epoch**. The server derives the next key and immediately **re-encrypts the entire message history**.
- **Result:** Removed members cannot decrypt future messages OR previous history using their old keys.

---

## Project Structure

- **`app.py`**: The Controller. Manages SocketIO events and real-time routing.
- **`state.py`**: The Orchestrator. Manages the collections of users and groups.
- **`user.py`**: The User Model. Handles P2P encryption, counters, and ECDH keys.
- **`group.py`**: The Group Model. Manages members, epochs, and history re-encryption.
- **`key_management.py`**: Asymmetric Logic. Encapsulates X25519 and Diffie-Hellman operations.
- **`utils.py`**: Symmetric Logic. Provides AES-GCM, HKDF, and Scrypt-based password utilities with Envelope Encryption.

---

## Setup steps

### Installation
```bash
pip install -r requirements.txt
```

### Usage
1. **Login:** Enter a username and password. The system handles registration automatically for new users.
2. **P2P Chat:** 
   - Enter the receiver's username and click on connect to setup a P2P chat through Key-exchange first. 
   - Send messages; the server stores only the encrypted hex-blobs.
3. **Group Management:**
   - Create a group with multiple members.
   - Add/Remove members using the specific buttons to trigger an Epoch update.
4. **On-Demand Decryption:**
   - Notice that the server never sends plaintext. The client UI automatically requests decryption for specific payloads using the authorized session/group keys.

---

## Cryptographic Primitives
- **Encryption:** AES-256-GCM (AEAD)
- **Key Exchange:** X25519 (Curve25519)
- **Key Derivation:** HKDF-SHA256
- **Password Hashing:** Scrypt + AES Encryption
- **Context Binding:** GCM Authenticated Data (AAD)
- **Storage:** Zero-Plaintext Policy (RAM-only)
