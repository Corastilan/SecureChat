"""
Local attack tests for the current packet/validation/replay design.

Run:
    python test_attacks.py
"""

import copy

from crypto_layer import KeyExchange, SecureStreamLayer

STREAM_ID = "secure_metrics_stream_v1"
SENDER_ID = "PRODUCER_01"
ATTACKER_ID = "MALLORY"

# Generate expensive parameters once so the test script stays fast.
_PARAMS = KeyExchange.get_params()
_KE = KeyExchange(_PARAMS)
_PUB_BYTES = _KE.get_public_bytes()
_SHARED_KEY = _KE.derive_static_key(_PUB_BYTES)


def setup_layers():
    producer = SecureStreamLayer(_SHARED_KEY, SENDER_ID, expected_stream_id=STREAM_ID)
    consumer = SecureStreamLayer(_SHARED_KEY, SENDER_ID, expected_stream_id=STREAM_ID)
    return producer, consumer


def print_header(title):
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)


def test_normal_flow():
    producer, consumer = setup_layers()
    packet = producer.encrypt('{"msg": "hello world"}', 0, stream_id=STREAM_ID)
    plaintext = consumer.decrypt(packet)
    print("Accepted plaintext:", plaintext)


def test_modification_attack():
    producer, consumer = setup_layers()
    packet = producer.encrypt('{"msg": "hello world"}', 0, stream_id=STREAM_ID)
    tampered = copy.deepcopy(packet)
    ct = bytearray.fromhex(tampered["ciphertext"])
    ct[0] ^= 0x01
    tampered["ciphertext"] = bytes(ct).hex()

    try:
        consumer.decrypt(tampered)
        print("FAIL: tampered packet was accepted")
    except Exception as exc:
        print("PASS: modification rejected ->", exc)


def test_spoofing_attack():
    producer, consumer = setup_layers()
    packet = producer.encrypt('{"msg": "hello world"}', 0, stream_id=STREAM_ID)
    spoofed = copy.deepcopy(packet)
    spoofed["sender_id"] = ATTACKER_ID

    try:
        consumer.decrypt(spoofed)
        print("FAIL: spoofed packet was accepted")
    except Exception as exc:
        print("PASS: spoofing rejected ->", exc)


def test_replay_attack_message_id_duplicate():
    producer, consumer = setup_layers()
    packet = producer.encrypt('{"msg": "hello world"}', 0, stream_id=STREAM_ID)
    first = consumer.decrypt(packet)
    print("First delivery accepted:", first)

    try:
        consumer.decrypt(packet)
        print("FAIL: replayed packet was accepted")
    except Exception as exc:
        print("PASS: replay rejected ->", exc)


def test_replay_attack_stale_counter():
    producer, consumer = setup_layers()
    p0 = producer.encrypt('{"msg": "zero"}', 0, stream_id=STREAM_ID)
    p1 = producer.encrypt('{"msg": "one"}', 1, stream_id=STREAM_ID)
    consumer.decrypt(p0)
    consumer.decrypt(p1)

    stale = producer.encrypt('{"msg": "stale"}', 1, stream_id=STREAM_ID)
    try:
        consumer.decrypt(stale)
        print("FAIL: stale counter packet was accepted")
    except Exception as exc:
        print("PASS: stale counter rejected ->", exc)


def test_stream_id_validation():
    producer, consumer = setup_layers()
    packet = producer.encrypt('{"msg": "hello world"}', 0, stream_id=STREAM_ID)
    wrong_stream = copy.deepcopy(packet)
    wrong_stream["stream_id"] = "other_stream"

    try:
        consumer.decrypt(wrong_stream)
        print("FAIL: wrong-stream packet was accepted")
    except Exception as exc:
        print("PASS: wrong stream rejected ->", exc)


def main():
    print_header("NORMAL FLOW")
    test_normal_flow()

    print_header("MODIFICATION ATTACK")
    test_modification_attack()

    print_header("SPOOFING ATTACK")
    test_spoofing_attack()

    print_header("REPLAY ATTACK: SAME MESSAGE ID")
    test_replay_attack_message_id_duplicate()

    print_header("REPLAY ATTACK: STALE COUNTER")
    test_replay_attack_stale_counter()

    print_header("STREAM/CONTEXT VALIDATION")
    test_stream_id_validation()


if __name__ == "__main__":
    main()
