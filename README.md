# Encrypted Systems: SecureChat & E2E Data Stream

Will be updated soon, stuff here for now.

## Overview

This repository contains two complementary projects built around end-to-end encryption and layered security design: **SecureChat**, a real-time encrypted messaging platform, and **E2E Secure Data Stream**, an encrypted pipeline using Redis as an untrusted intermediary. Both share a common cryptographic foundation. AES-256-GCM, HKDF-SHA256, and authenticated metadata binding while targeting different threat models.

---

## Security Architecture

### Account Security: Envelope Encryption (SecureChat)

Passwords are "double-locked" rather than simply hashed:

- **Primary layer (hashing):** Passwords are processed with Scrypt, a memory-hard algorithm resistant to GPU/ASIC brute-forcing. Each hash uses a unique 16-byte random salt.
- **Secondary layer (encryption):** The resulting hash is then encrypted with a 32-byte server-side Master Pepper using AES-256-GCM.
- **Benefit:** An attacker must compromise both the database and the server's environment to attempt a crack.

### Peer-to-Peer Security: The Secure Tunnel (SecureChat)

- **Identity exchange:** Users perform an X25519 (ECDH) handshake to establish a shared secret without transmitting it.
- **Key derivation:** HKDF (SHA-256) with application-specific context derives a unique symmetric AES-256 session key.
- **Context binding:** Every message is bound via AAD to the specific `sender`, `receiver`, and a `counter`, preventing replay and reflection attacks.

### Group Security: Epoch-Based Ratcheting (SecureChat)

- **Master seed:** Groups are initialized with a unique `master_seed`.
- **Epoch distribution:** The actual encryption key is derived via `HKDF(Master_Seed, Group_ID, Epoch)`.
- **Forward/backward secrecy:** Whenever membership changes (add/remove), the group increments its epoch. The server derives the next key and immediately re-encrypts the entire message history, so removed members cannot decrypt future messages or previous history using their old keys.

### Stream Security: Authenticated Packet Design (E2E Data Stream)

Each transmitted packet contains: `version`, `sender_id`, `stream_id`, `message_id`, `counter`, `timestamp`, `nonce`, and `ciphertext`.

The following fields are authenticated as GCM associated data: `version`, `sender_id`, `stream_id`, `message_id`, `counter`, `timestamp`. Any tampering with either the ciphertext or authenticated metadata causes decryption to fail.

**Receiver-side validation flow:**

1. Verify all required packet fields are present and well-formed.
2. Verify the protocol version.
3. Verify the `stream_id` belongs to the expected stream context.
4. Reject duplicate `message_id` values.
5. Reject stale per-sender counters.
6. Verify AES-GCM authenticity and integrity.
7. Decrypt and display plaintext only if all checks pass.

**Attack cases covered:**

- **Eavesdropping:** Intercepted packets reveal no plaintext without the key.
- **Modification:** Changing ciphertext or authenticated metadata causes verification failure.
- **Spoofing:** Changing `sender_id` or other authenticated metadata invalidates the packet.
- **Replay:** Duplicate `message_id` values or stale counters are rejected.

---

## Cryptographic Primitives

| Primitive | Usage |
|---|---|
| AES-256-GCM | Encryption and integrity (both projects) |
| X25519 (Curve25519) | P2P key exchange (SecureChat) |
| HKDF-SHA256 | Key derivation (both projects) |
| Scrypt + AES | Password hashing with envelope encryption (SecureChat) |
| GCM AAD | Context binding — sender, receiver, counter, packet metadata |
| Monotonic counters + `message_id` | Replay protection (Data Stream) |

Both projects enforce a **zero-plaintext storage policy**: the server stores only encrypted blobs; plaintext exists only in memory at the client.

---

## Project Structure

### SecureChat

- **`app.py`** — Controller; manages SocketIO events and real-time routing.
- **`state.py`** — Orchestrator; manages collections of users and groups.
- **`user.py`** — User model; handles P2P encryption, counters, and ECDH keys.
- **`group.py`** — Group model; manages members, epochs, and history re-encryption.
- **`key_management.py`** — Asymmetric logic; encapsulates X25519 and Diffie-Hellman operations.
- **`utils.py`** — Symmetric logic; provides AES-GCM, HKDF, and Scrypt-based password utilities with envelope encryption.

### E2E Data Stream

- **`producer.py`** — Encrypts and publishes packets to Redis.
- **`consumer.py`** — Receives, validates, and decrypts packets.
- **`test_attacks.py`** — Optional attack simulation tests.

---

## Setup & Usage

### SecureChat

**Installation:**
```bash
pip install -r requirements.txt
```

**Usage:**

1. **Login:** Enter a username and password. Registration is handled automatically for new users.
2. **P2P chat:** Enter the receiver's username and click Connect to initiate a key exchange, then send messages. The server stores only encrypted hex blobs.
3. **Group management:** Create a group with multiple members. Use Add/Remove buttons to trigger an epoch update.
4. **On-demand decryption:** The client UI automatically requests decryption for specific payloads using authorized session or group keys — the server never sends plaintext.

### E2E Data Stream

**Requirements:** Redis must be running.

```bash
brew services start redis
pip install -r requirements.txt
```

**Running:**
```bash
# Terminal 1
python producer.py

# Terminal 2
python consumer.py

# Optional: simulate attack cases
python test_attacks.py
```
