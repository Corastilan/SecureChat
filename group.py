from dataclasses import dataclass
from typing import List, Set

from utils import Utils

"""
1. _derive_current_key : Derives the current AES key for the group based on master_seed, group_id, and epoch.
2. aad_for: generates the additional data for message encryption
3. add_member/remove_member: add/remove user and creates a new symmetric key for all users
4. encrypt_and_store: encrypt the PT msg and store it in the group memory
5. decrypt_payload: Decrypt the stored message
6. rotate_epoch: Move the epoch forward to derive the next key.
7. history_encrypted: List of encrypted messages in the group
"""


@dataclass
class EncryptedGroupMessage:
    msg_id: int
    sender: str
    nonce: bytes
    ciphertext: bytes


class Group:
    def __init__(self, group_id: str, members: Set[str]):
        self.group_id = group_id
        self.members = set(members)
        self.master_seed = Utils.random_key_32()
        self.epoch = 0
        self.aes_key = self._derive_current_key()

        self.next_msg_id = 1
        self.messages: List[EncryptedGroupMessage] = []

    def _derive_current_key(self) -> bytes:
        return Utils.derive_group_epoch_key(self.master_seed, self.group_id, self.epoch)

    def _aad_for(self, sender: str, msg_id: int, epoch: int) -> bytes:
        return (
            f"group:{self.group_id}:sender:{sender}:msg:{msg_id}:epoch:{epoch}".encode(
                "utf-8"
            )
        )

    def add_member(self, actor: str, new_member: str):
        if actor not in self.members:
            raise ValueError("Only current members can add someone.")
        if new_member in self.members:
            return
        self.members.add(new_member)
        self.rotate_epoch()

    def remove_member(self, actor: str, member_to_remove: str):
        if actor not in self.members:
            raise ValueError("Only current members can remove someone.")
        if member_to_remove not in self.members:
            return
        self.members.remove(member_to_remove)
        self.rotate_epoch()

    def rotate_epoch(self):
        old_key = self.aes_key
        old_epoch = self.epoch

        self.epoch += 1
        self.aes_key = self._derive_current_key()

        for m in self.messages:
            old_aad = self._aad_for(m.sender, m.msg_id, old_epoch)
            new_aad = self._aad_for(m.sender, m.msg_id, self.epoch)

            pt = Utils.decrypt_aes_gcm(old_key, m.nonce, m.ciphertext, old_aad)
            new_nonce, new_ct = Utils.encrypt_aes_gcm(self.aes_key, pt, new_aad)
            m.nonce = new_nonce
            m.ciphertext = new_ct

    def encrypt_and_store(self, sender: str, plaintext: str) -> EncryptedGroupMessage:
        if sender not in self.members:
            raise ValueError("Sender is not a member of this group.")
        msg_id = self.next_msg_id
        self.next_msg_id += 1
        aad = self._aad_for(sender, msg_id, self.epoch)
        nonce, ct = Utils.encrypt_aes_gcm(self.aes_key, plaintext, aad)
        m = EncryptedGroupMessage(
            msg_id=msg_id, sender=sender, nonce=nonce, ciphertext=ct
        )
        self.messages.append(m)
        return m

    def decrypt_payload(
        self, sender: str, msg_id: int, nonce: bytes, ciphertext: bytes, epoch: int
    ) -> str:
        aad = self._aad_for(sender, msg_id, epoch)
        key_for_epoch = Utils.derive_group_epoch_key(
            self.master_seed, self.group_id, epoch
        )
        return Utils.decrypt_aes_gcm(key_for_epoch, nonce, ciphertext, aad)

    def history_encrypted(self) -> List[dict]:
        return [
            {
                "group_id": self.group_id,
                "msg_id": m.msg_id,
                "from": m.sender,
                "epoch": self.epoch,
                "nonce_hex": m.nonce.hex(),
                "ciphertext_hex": m.ciphertext.hex(),
            }
            for m in self.messages
        ]
