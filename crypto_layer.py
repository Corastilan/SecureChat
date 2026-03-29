import os
import time
import uuid
from typing import Any, Dict

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class SecureStreamLayer:
    """
    Secure packet layer for the producer/consumer stream.

    Responsibilities:
    - define the message packet format
    - bind important metadata to the ciphertext via AEAD associated data
    - enforce receiver-side validation rules
    - reject replayed packets using per-sender counters and message IDs
    """

    PROTOCOL_VERSION = 1

    def __init__(
        self, key: bytes, local_sender_id: str, expected_stream_id: str | None = None
    ):
        self.aesgcm = AESGCM(key)
        self.local_sender_id = local_sender_id
        self.expected_stream_id = expected_stream_id

        # Replay-defense state.
        self.last_received_counter_by_sender: Dict[str, int] = {}
        self.seen_message_ids: set[str] = set()

    def _build_associated_data(
        self,
        *,
        version: int,
        sender_id: str,
        stream_id: str,
        message_id: str,
        counter: int,
        timestamp: int,
    ) -> bytes:
        """
        Metadata authenticated but not encrypted.
        If any of these values are modified, AES-GCM verification will fail.
        """
        ad = "|".join(
            [
                str(version),
                sender_id,
                stream_id,
                message_id,
                str(counter),
                str(timestamp),
            ]
        )
        return ad.encode("utf-8")

    def encrypt(
        self, plaintext: str, counter: int, *, stream_id: str
    ) -> Dict[str, Any]:
        if counter < 0:
            raise ValueError("Counter must be non-negative.")

        nonce = os.urandom(12)
        timestamp = int(time.time())
        message_id = str(uuid.uuid4())

        packet = {
            "version": self.PROTOCOL_VERSION,
            "sender_id": self.local_sender_id,
            "stream_id": stream_id,
            "message_id": message_id,
            "counter": counter,
            "timestamp": timestamp,
            "nonce": nonce.hex(),
        }

        associated_data = self._build_associated_data(
            version=packet["version"],
            sender_id=packet["sender_id"],
            stream_id=packet["stream_id"],
            message_id=packet["message_id"],
            counter=packet["counter"],
            timestamp=packet["timestamp"],
        )

        ciphertext = self.aesgcm.encrypt(
            nonce, plaintext.encode("utf-8"), associated_data
        )
        packet["ciphertext"] = ciphertext.hex()
        return packet

    def _validate_packet_shape(self, packet: Dict[str, Any]) -> None:
        required_fields = {
            "version": int,
            "sender_id": str,
            "stream_id": str,
            "message_id": str,
            "counter": int,
            "timestamp": int,
            "nonce": str,
            "ciphertext": str,
        }

        missing = [field for field in required_fields if field not in packet]
        if missing:
            raise ValueError(f"Malformed packet: missing required fields {missing}.")

        for field, expected_type in required_fields.items():
            if not isinstance(packet[field], expected_type):
                raise ValueError(
                    f"Malformed packet: field '{field}' must be {expected_type.__name__}."
                )

        if packet["version"] != self.PROTOCOL_VERSION:
            raise ValueError(
                f"Unsupported protocol version: {packet['version']} != {self.PROTOCOL_VERSION}."
            )

        if packet["counter"] < 0:
            raise ValueError("Malformed packet: counter must be non-negative.")

        if (
            self.expected_stream_id is not None
            and packet["stream_id"] != self.expected_stream_id
        ):
            raise ValueError(
                f"Unexpected stream_id '{packet['stream_id']}'. Expected '{self.expected_stream_id}'."
            )

        try:
            nonce = bytes.fromhex(packet["nonce"])
        except ValueError as exc:
            raise ValueError("Malformed packet: nonce is not valid hex.") from exc
        if len(nonce) != 12:
            raise ValueError("Malformed packet: AES-GCM nonce must be 12 bytes.")

        try:
            bytes.fromhex(packet["ciphertext"])
        except ValueError as exc:
            raise ValueError("Malformed packet: ciphertext is not valid hex.") from exc

    def _check_replay(self, packet: Dict[str, Any]) -> None:
        sender_id = packet["sender_id"]
        counter = packet["counter"]
        message_id = packet["message_id"]

        if message_id in self.seen_message_ids:
            raise Exception(
                f"REPLAY ATTACK: Message ID {message_id} was already accepted."
            )

        last_counter = self.last_received_counter_by_sender.get(sender_id, -1)
        if counter <= last_counter:
            raise Exception(
                f"REPLAY ATTACK: Counter {counter} is stale for sender {sender_id}. "
                f"Last accepted counter was {last_counter}."
            )

    def decrypt(self, packet: Dict[str, Any]) -> str:
        self._validate_packet_shape(packet)
        self._check_replay(packet)

        nonce = bytes.fromhex(packet["nonce"])
        ciphertext = bytes.fromhex(packet["ciphertext"])
        associated_data = self._build_associated_data(
            version=packet["version"],
            sender_id=packet["sender_id"],
            stream_id=packet["stream_id"],
            message_id=packet["message_id"],
            counter=packet["counter"],
            timestamp=packet["timestamp"],
        )

        # AES-GCM verifies authenticity and integrity here.
        decrypted_data = self.aesgcm.decrypt(nonce, ciphertext, associated_data)

        self.seen_message_ids.add(packet["message_id"])
        self.last_received_counter_by_sender[packet["sender_id"]] = packet["counter"]
        return decrypted_data.decode("utf-8")


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
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def derive_static_key(self, public_key_bytes: bytes) -> bytes:
        """
        Derives a deterministic key from a public key.
        In a broadcast model, all authorized parties derive the same
        session key from the Producer's public identity.
        """
        # We use the public key as the source of entropy for the session key
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"nyu-salt",  # Fixed salt for session sync
            info=b"nyu-vapt-stream-project",
        ).derive(public_key_bytes)
