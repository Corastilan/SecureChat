# E2E Secure Data Stream

## Overview
This project implements an end-to-end encrypted data pipeline using Redis as an untrusted intermediary. It protects against eavesdropping, modification, spoofing, and replay attacks.

## Current Packet Format
Each transmitted packet contains:
- `version`
- `sender_id`
- `stream_id`
- `message_id`
- `counter`
- `timestamp`
- `nonce`
- `ciphertext`

The encrypted payload uses AES-256-GCM. The following metadata is authenticated as associated data:
- `version`
- `sender_id`
- `stream_id`
- `message_id`
- `counter`
- `timestamp`

This means that any tampering with either the ciphertext or the authenticated metadata causes decryption to fail.

## Receiver-Side Validation Flow
When a consumer receives a packet, it:
1. Checks that all required packet fields are present and well-formed.
2. Verifies the protocol version.
3. Verifies the `stream_id` belongs to the expected stream context.
4. Rejects duplicate `message_id` values.
5. Rejects stale per-sender counters.
6. Verifies AES-GCM authenticity/integrity.
7. Decrypts and displays the plaintext only if all checks pass.

## Security Design
- **Confidentiality & Integrity:** AES-256-GCM (AEAD)
- **Key Exchange:** parameter broadcast + repo-compatible HKDF-based shared-key derivation
- **Authenticity:** sender and packet metadata are bound to the ciphertext via GCM associated data
- **Replay Protection:** monotonic counters plus unique `message_id` tracking

## Attack Cases Covered
- **Eavesdropping:** intercepted packets do not reveal plaintext without the key.
- **Modification:** changing ciphertext or authenticated metadata causes verification failure.
- **Spoofing:** changing `sender_id` or other authenticated metadata invalidates the packet.
- **Replay:** duplicate `message_id` values or stale counters are rejected.

## How to Run
1. Ensure Redis is running: `brew services start redis`
2. Install dependencies: `pip install -r requirements.txt`
3. Terminal 1: `python producer.py`
4. Terminal 2: `python consumer.py`
5. Optional attack tests: `python test_attacks.py`