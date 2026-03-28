import threading
from typing import Dict, List, Set, Optional

from user import User
from group import Group
from key_management import KeyManager
from utils import PasswordHasher

""" Crux of the implementation.
1. login_user: Verify or Register user with hashed password
2. list_group_for_user: lists the groups that user is part of
3. connect_p2p: Establish P2P connection by calculating shared AES key using X25519 (DH EC) key exchange.
4. send_p2p_message: Validate session existence and use the user level encryption to send an encrypted payload to the receiver
5. decrypt_p2p_payload: Proxy for calling the user level decrypt
6. get_p2p_history: Lists encrypted messages that were previously sent by different users
7. create_group, add, remove member, send group message and decrypt group payload are the respective group functions
"""

class ServerState:
    def __init__(self):
        self.lock = threading.Lock()
        self.users: Dict[str, User] = {}
        self.passwords: Dict[str, str] = {}
        self.groups: Dict[str, Group] = {}
        self.p2p_history: Dict[str, List[dict]] = {}

    def login_user(self, username: str, password: str, sid: str) -> dict:
        with self.lock:
            if username in self.passwords:
                if not PasswordHasher.verify_password(self.passwords[username], password):
                    raise ValueError("Invalid username or password.")
                self.users[username].sid = sid
                is_new = False
            else:
                self.passwords[username] = PasswordHasher.hash_password(password)
                self.users[username] = User.create(username=username, sid=sid)
                is_new = True
            
            return {"user": self.users[username], "is_new": is_new}

    def list_groups_for_user(self, username: str) -> List[str]:
        with self.lock:
            return [gid for gid, g in self.groups.items() if username in g.members]

    def connect_p2p(self, a: str, b: str) -> None:
        with self.lock:
            if a not in self.users or b not in self.users:
                raise ValueError("Both users must be connected first.")
            ua = self.users[a]
            ub = self.users[b]
            ua.p2p_keys[b] = KeyManager.compute_p2p_key(ua.x_priv, ub.x_pub_bytes)
            ub.p2p_keys[a] = KeyManager.compute_p2p_key(ub.x_priv, ua.x_pub_bytes)

    def send_p2p_message(self, sender: str, peer: str, plaintext: str) -> dict:
        with self.lock:
            if sender not in self.users or peer not in self.users:
                raise ValueError("Both users must be connected first.")
            us = self.users[sender]
            up = self.users[peer]
            
            count, nonce, ct = us.encrypt_for_peer(peer_username=peer, plaintext=plaintext)
            
            encrypted_payload = {
                "from": sender,
                "to": peer,
                "count": count,
                "nonce_hex": nonce.hex(),
                "ciphertext_hex": ct.hex(),
            }
            
            self.p2p_history.setdefault(sender, []).append(encrypted_payload)
            self.p2p_history.setdefault(peer, []).append(encrypted_payload)
            
            return {
                "to_sid": up.sid,
                **encrypted_payload
            }

    def decrypt_p2p_payload(self, receiver: str, sender: str, count: int, nonce_hex: str, ciphertext_hex: str) -> str:
        with self.lock:
            if receiver not in self.users:
                raise ValueError("Receiver not connected.")
            return self.users[receiver].decrypt_from_peer(peer_username=sender, count=count, nonce=bytes.fromhex(nonce_hex), ciphertext=bytes.fromhex(ciphertext_hex))

    def get_p2p_history(self, username: str) -> List[dict]:
        with self.lock:
            return self.p2p_history.get(username, [])

    def _require_group(self, group_id: str) -> Group:
        if group_id not in self.groups:
            raise ValueError("Unknown group.")
        return self.groups[group_id]

    def create_group(self, group_id: str, creator: str, members: List[str]) -> None:
        with self.lock:
            if group_id in self.groups:
                raise ValueError("Group already exists.")
            member_set = set(members)
            member_set.add(creator)
            self.groups[group_id] = Group(group_id=group_id, members=member_set)

    def add_member(self, group_id: str, actor: str, new_member: str) -> None:
        with self.lock:
            g = self._require_group(group_id)
            g.add_member(actor, new_member)

    def remove_member(self, group_id: str, actor: str, member: str) -> None:
        with self.lock:
            g = self._require_group(group_id)
            g.remove_member(actor, member)

    def send_group_message(self, group_id: str, sender: str, plaintext: str) -> dict:
        with self.lock:
            g = self._require_group(group_id)
            m = g.encrypt_and_store(sender, plaintext)
            
            return {
                "group_id": group_id,
                "from": m.sender,
                "msg_id": m.msg_id,
                "epoch": g.epoch,
                "nonce_hex": m.nonce.hex(),
                "ciphertext_hex": m.ciphertext.hex(),
                "members": list(g.members)
            }

    def decrypt_group_payload(self, receiver: str, group_id: str, sender: str, msg_id: int, epoch: int, nonce_hex: str, ciphertext_hex: str) -> str:
        with self.lock:
            g = self._require_group(group_id)
            if receiver not in g.members:
                raise ValueError("Not a member of this group.")
            return g.decrypt_payload(sender=sender, msg_id=msg_id, epoch=epoch, nonce=bytes.fromhex(nonce_hex), ciphertext=bytes.fromhex(ciphertext_hex))
