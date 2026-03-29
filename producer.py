import json
import time

import psutil
import redis
from cryptography.hazmat.primitives import serialization

from crypto_layer import KeyExchange, SecureStreamLayer

# Create redis client for packet publishing
r = redis.Redis(host="localhost", port=6379, db=0)

# Fixed identifiers for metadata
STREAM_ID = "secure_metrics_stream_v1"
SENDER_ID = "PRODUCER_01"

# Clear the old session so consumers don't get confused
r.delete("key_exchange_channel")

# Generate Diffie-Helman parameters
print("[Producer] Generating DH Parameters (2048-bit)...")
params = KeyExchange.get_params()
param_pem = params.parameter_bytes(
    serialization.Encoding.PEM,
    serialization.ParameterFormat.PKCS3,
)

# Create Producer's instance
ke = KeyExchange(params)
pub_bytes = ke.get_public_bytes()

# Save handshake to Redis
r.set(
    "key_exchange_channel",
    json.dumps(
        {
            "params": param_pem.decode(),
            "pub_key": pub_bytes.decode(),
            "stream_id": STREAM_ID,
            "sender_id": SENDER_ID,
            "protocol_version": SecureStreamLayer.PROTOCOL_VERSION,
        }
    ),
)

# Derive the session key (Self-derivation for broadcast)
shared_key = ke.derive_static_key(pub_bytes)
secure = SecureStreamLayer(shared_key, SENDER_ID, expected_stream_id=STREAM_ID)

# Message counter (for anti-replay)
counter = 0

# Start sending loop (current metric payload)
print("[Producer] Handshake ready. Starting stream...")
while True:
    try:
        metric = json.dumps(
            {
                "cpu": psutil.cpu_percent(),
                "mem": psutil.virtual_memory().percent,
            }
        )
        packet = secure.encrypt(metric, counter, stream_id=STREAM_ID)
        r.publish("secure_metrics_stream", json.dumps(packet))
        print(f"Sent packet {counter}: {metric}")
        counter += 1
        time.sleep(2)
    except KeyboardInterrupt:
        break
