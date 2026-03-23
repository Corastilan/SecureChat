import redis
import json
import time
from crypto_layer import SecureStreamLayer, KeyExchange
from cryptography.hazmat.primitives import serialization

r = redis.Redis(host='localhost', port=6379, db=0)

print("[Consumer] Looking for Producer's Handshake...")
while not r.exists("key_exchange_channel"):
    time.sleep(1)

# Fetch the handshake data
handshake = json.loads(r.get("key_exchange_channel"))
params = serialization.load_pem_parameters(handshake['params'].encode())
producer_pub_key = handshake['pub_key'].encode()

# Derive the EXACT same key as the Producer
ke = KeyExchange(params)
shared_key = ke.derive_static_key(producer_pub_key)
secure = SecureStreamLayer(shared_key, "PRODUCER_01")

print("[Consumer] Key Derived Successfully. Listening to stream...")

pubsub = r.pubsub()
pubsub.subscribe("secure_metrics_stream")

for message in pubsub.listen():
    if message['type'] == 'message':
        packet = json.loads(message['data'])
        try:
            # SecureStreamLayer handles Decryption, Integrity, and Replay
            decrypted_msg = secure.decrypt(packet)
            print(f"Decrypted Data: {decrypted_msg}")
        except Exception as e:
            print(f"!!! SECURITY ALERT !!! {e}")