from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit

from state import ServerState

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev"
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

state = ServerState()


@app.route("/")
def index():
    return render_template("index.html")


@socketio.on("connect")
def on_connect():
    print(f"[socket] connected sid={request.sid}")
    emit("system", {"message": "Socket connected."})


@socketio.on("login")
def on_login(data):
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    if not username or not password:
        return emit("error", {"message": "Username and password required."})

    sid = request.sid
    print(f"[socket] login attempt username={username} sid={sid}")
    try:
        result = state.login_user(username, password, sid)
        is_new = result["is_new"]
        print(f"[socket] login successful: {username} (new={is_new})")
    except Exception as e:
        print(f"[socket] login error: {e}")
        return emit("error", {"message": str(e)})

    emit("logged_in", {"user": username, "is_new": is_new})

    p2p_hist = state.get_p2p_history(username)
    if p2p_hist:
        emit("p2p_history", {"messages": p2p_hist})

    groups = state.list_groups_for_user(username)
    for group_id in groups:
        g = state.groups[group_id]
        emit("group_history", {"group_id": group_id, "messages": g.history_encrypted()})


@socketio.on("connect_peer")
def on_connect_peer(data):
    username = data.get("username", "").strip()
    peer = data.get("peer", "").strip()
    if not username or not peer:
        return emit("error", {"message": "username and peer are required."})
    try:
        state.connect_p2p(username, peer)
        emit("system", {"message": f"P2P ready between {username} and {peer}."})
    except Exception as e:
        emit("error", {"message": str(e)})


@socketio.on("send_p2p")
def on_send_p2p(data):
    username = data.get("username", "").strip()
    peer = data.get("peer", "").strip()
    msg = data.get("message", "")
    if not username or not peer:
        return emit("error", {"message": "username and peer are required."})

    try:
        payload = state.send_p2p_message(sender=username, peer=peer, plaintext=msg)
        socketio.emit(
            "p2p_payload",
            {
                "from": payload["from"],
                "count": payload["count"],
                "nonce_hex": payload["nonce_hex"],
                "ciphertext_hex": payload["ciphertext_hex"],
            },
            room=payload["to_sid"],
        )
        emit("system", {"message": f"Sent encrypted P2P message to {peer}."})
    except Exception as e:
        emit("error", {"message": str(e)})


@socketio.on("decrypt_p2p")
def on_decrypt_p2p(data):
    receiver = data.get("username", "").strip()
    sender = data.get("from", "").strip()
    nonce_hex = data.get("nonce_hex", "").strip()
    ciphertext_hex = data.get("ciphertext_hex", "").strip()
    try:
        count = int(data.get("count"))
    except (TypeError, ValueError):
        return emit("error", {"message": "Invalid message count."})

    try:
        plaintext = state.decrypt_p2p_payload(
            receiver=receiver,
            sender=sender,
            count=count,
            nonce_hex=nonce_hex,
            ciphertext_hex=ciphertext_hex,
        )
        emit("p2p_message", {"from": sender, "message": plaintext})
    except Exception as e:
        emit("error", {"message": str(e)})


@socketio.on("create_group")
def on_create_group(data):
    group_id = data.get("group_id", "").strip()
    creator = data.get("username", "").strip()
    members = data.get("members", [])
    if not group_id or not creator:
        return emit("error", {"message": "group_id and username are required."})
    try:
        state.create_group(group_id=group_id, creator=creator, members=members)
        emit("system", {"message": f"Group {group_id} created."})
    except Exception as e:
        emit("error", {"message": str(e)})


@socketio.on("add_group_member")
def on_add_group_member(data):
    group_id = data.get("group_id", "").strip()
    actor = data.get("username", "").strip()
    new_member = data.get("member", "").strip()
    if not group_id or not actor or not new_member:
        return emit("error", {"message": "group_id, username, member required."})

    try:
        state.add_member(group_id=group_id, actor=actor, new_member=new_member)
        emit(
            "system",
            {"message": f"Added {new_member} to {group_id} and rotated group key."},
        )

        connected = state.users.get(new_member)
        if connected:
            hist = state.groups[group_id].history_encrypted()
            socketio.emit(
                "group_history",
                {"group_id": group_id, "messages": hist},
                room=connected.sid,
            )
    except Exception as e:
        emit("error", {"message": str(e)})


@socketio.on("remove_group_member")
def on_remove_group_member(data):
    group_id = data.get("group_id", "").strip()
    actor = data.get("username", "").strip()
    member = data.get("member", "").strip()
    if not group_id or not actor or not member:
        return emit("error", {"message": "group_id, username, member required."})

    try:
        state.remove_member(group_id=group_id, actor=actor, member=member)
        emit(
            "system",
            {"message": f"Removed {member} from {group_id} and rotated group key."},
        )
    except Exception as e:
        emit("error", {"message": str(e)})


@socketio.on("send_group")
def on_send_group(data):
    group_id = data.get("group_id", "").strip()
    sender = data.get("username", "").strip()
    msg = data.get("message", "")
    if not group_id or not sender:
        return emit("error", {"message": "group_id and username required."})

    try:
        payload = state.send_group_message(
            group_id=group_id, sender=sender, plaintext=msg
        )
        for member in payload["members"]:
            sess = state.users.get(member)
            if sess:
                socketio.emit(
                    "group_payload",
                    {
                        "group_id": payload["group_id"],
                        "from": payload["from"],
                        "msg_id": payload["msg_id"],
                        "epoch": payload["epoch"],
                        "nonce_hex": payload["nonce_hex"],
                        "ciphertext_hex": payload["ciphertext_hex"],
                    },
                    room=sess.sid,
                )
    except Exception as e:
        emit("error", {"message": str(e)})


@socketio.on("decrypt_group")
def on_decrypt_group(data):
    receiver = data.get("username", "").strip()
    group_id = data.get("group_id", "").strip()
    sender = data.get("from", "").strip()
    nonce_hex = data.get("nonce_hex", "").strip()
    ciphertext_hex = data.get("ciphertext_hex", "").strip()
    try:
        msg_id = int(data.get("msg_id"))
        epoch = int(data.get("epoch"))
    except (TypeError, ValueError):
        return emit("error", {"message": "Invalid message or epoch ID."})

    try:
        plaintext = state.decrypt_group_payload(
            receiver=receiver,
            group_id=group_id,
            sender=sender,
            msg_id=msg_id,
            epoch=epoch,
            nonce_hex=nonce_hex,
            ciphertext_hex=ciphertext_hex,
        )
        emit(
            "group_message",
            {"group_id": group_id, "from": sender, "message": plaintext},
        )
    except Exception as e:
        emit("error", {"message": str(e)})


if __name__ == "__main__":
    socketio.run(app, debug=True, port=5001, allow_unsafe_werkzeug=True)
