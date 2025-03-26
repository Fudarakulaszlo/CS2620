# follower.py
import socket
import threading
import os
import sys
import json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.protocol import *
from responses import *
from log_util import append_to_log, replay_log

LOG_PATH = f"common/logs/follower.log"

# Load stored usernames & passwords
def load_users():
    if not os.path.exists(USERS_FILE): 
        print("❗ No user found. Creating a default user.")
        hash_psw = hash_password_sha256("Yunlei1207~")
        users = {"kakali121": hash_psw}
        # Save one user to file
        with open(USERS_FILE, "w") as f: json.dump(users, f)
        # Create a message file for the user
        user_message_file = os.path.join(MESSAGES_DIR, "kakali121.dat")
        # Create a new message file for the user
        with open(user_message_file, "w") as f: f.write("")
    else: # Load existing users
        try:
            with open(USERS_FILE, "r") as f: users = json.load(f)
        except json.JSONDecodeError:
            print("❗ Error reading user file, resetting it.")
            hash_psw = hash_password_sha256("Yunlei1207~")
            users = {"kakali121": hash_psw}
            with open(USERS_FILE, "w") as f: json.dump(users, f)
            # Create a message file for the user
            user_message_file = os.path.join(MESSAGES_DIR, "kakali121.dat")
            # Create a new message file for the user
            with open(user_message_file, "w") as f: f.write("")
    return users

def handle_replication(conn, users):
    try:
        packet = conn.recv(BUFFER_SIZE)
        cmd, payload, status = parse_packet(packet)

        if status != RES_OK:
            conn.sendall(create_packet(RES_ERR_REQ_FMT, "Invalid packet."))
            return

        append_to_log(LOG_PATH, cmd, payload)

        if cmd == REQ_REG:
            username, password = payload.split("|")
            handle_reg(conn, users, username, password)
        elif cmd == REQ_SET:
            username, message, target = payload.split("|")
            handle_set(conn, users, username, message, target)
        elif cmd == REQ_DEL:
            username = payload
            handle_delete(conn, users, username)
        elif cmd == REQ_JOI:
            # Just acknowledge that the follower is alive and joinable
            conn.sendall(create_packet(RES_OK, "✅ Ready to join replication."))
            return
        else:
            conn.sendall(create_packet(RES_ERR_UNIMPLEMENTED, "Unsupported replicated command."))
            return
        # If successful
        conn.sendall(create_packet(RES_OK, "ACK"))
    except Exception as e:
        print(f"❌ Error in follower: {e}")
        conn.sendall(create_packet(RES_ERR_SERVER, "Internal error."))
    finally:
        conn.close()

def start_follower(port):
    LOG_PATH = "common/logs/follower_{port}.log"
    users = load_users()

    # Replay existing log to rebuild state
    entries = replay_log(LOG_PATH)
    for entry in entries:
        cmd, payload = entry["cmd"], entry["payload"]
        if cmd == "REQ_REG":
            username, password = payload.split("|")
            handle_reg(None, users, username, password)
        elif cmd == "REQ_SET":
            username, message, target = payload.split("|")
            handle_set(None, users, username, message, target)
        elif cmd == "REQ_DEL":
            handle_delete(None, users, payload)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(25)
    print(f"📡 Follower listening on port {port}...")

    while True:
        conn, _ = s.accept()
        threading.Thread(target=handle_replication, args=(conn, users), daemon=True).start()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 follower.py <port>")
        sys.exit(1)

    port = int(sys.argv[1])
    start_follower(port)