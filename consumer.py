import json
import time

import redis
from cryptography.hazmat.primitives import serialization

from crypto_layer import KeyExchange, SecureStreamLayer

# Create redis client for packet receiving
r = redis.Redis(host="localhost", port=6379, db=0)

# Wait to receive handshake
print("[Consumer] Looking for producer handshake...")
while not r.exists("key_exchange_channel"):
    time.sleep(1)

# Fetch the handshake data
handshake = json.loads(r.get("key_exchange_channel"))
params = serialization.load_pem_parameters(handshake['params'].encode())
producer_pub_key = handshake["pub_key"].encode()
expected_stream_id = handshake.get("stream_id", "secure_metrics_stream_v1")
expected_sender_id = handshake.get("sender_id", "PRODUCER_01")

# Derive the EXACT same key as the Producer
ke = KeyExchange(params)
shared_key = ke.derive_static_key(producer_pub_key)
secure = SecureStreamLayer(shared_key, expected_sender_id, expected_stream_id=expected_stream_id)

print("[Consumer] Key derived successfully. Listening to stream...")

pubsub = r.pubsub()
pubsub.subscribe("secure_metrics_stream")

for message in pubsub.listen():
    if message["type"] == "message":
        packet = json.loads(message["data"])
        try:
            # SecureStreamLayer handles Decryption, Integrity, and Replay
            decrypted_msg = secure.decrypt(packet)
            print(f"Decrypted data: {decrypted_msg}")
        except Exception as e:
            print(f"!!! SECURITY ALERT !!! {e}")
