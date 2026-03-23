# E2E Secure Data Stream

## Overview
This project implements an end-to-end (E2E) encrypted data pipeline using Redis as an untrusted intermediary. It protects against Eavesdropping, Modification, Spoofing, and Replay attacks.

## Security Design
- **Confidentiality & Integrity:** AES-256-GCM (AEAD).
- **Key Exchange:** Diffie-Hellman (2048-bit) with HKDF for key derivation.
- **Authenticity:** Sender ID bound to Ciphertext via GCM Associated Data.
- **Replay Protection:** Monotonic counters included in the authenticated header.

## How to Run
1. Ensure Redis is running `brew services start redis`.
2. Install dependencies: `pip install -r requirements.txt`.
3. Terminal 1: `python producer.py`
4. Terminal 2: `python consumer.py`