"""
* responses.py
* Author: Áron Vékássy, Karen Li

This file handles client requests and generates structured responses 
using the custom wire protocol.
"""

import os
import sys
import json

# Add parent directory to module search path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.protocol import *
from common.json_protocol import *

# Node-specific values, set at runtime
NODE_ID = None
MESSAGES_DIR = None
USERS_FILE = None

def set_node_id(node_id):
    """
    Called once from node.py to set per-node directory and user file paths.
    Each node stores messages and user data separately.
    """
    global NODE_ID, MESSAGES_DIR, USERS_FILE
    NODE_ID = node_id

    # Messages go in e.g. `common/messages/node_2/...`
    MESSAGES_DIR = os.path.join("common", "messages", f"node_{NODE_ID}")
    os.makedirs(MESSAGES_DIR, exist_ok=True)

    # Each node’s users file can be e.g. `common/users/node_2_users.dat`
    os.makedirs("common/users", exist_ok=True)
    USERS_FILE = os.path.join("common", "users", f"node_{NODE_ID}_users.dat")

def send_response(client_socket, status, payload=""):
    """Send a structured response to the client."""
    if USE_JSON:
        if isinstance(status, bytes):
            status = status.decode() 
        response_str = create_json(status, payload)
        client_socket.sendall(response_str.encode())
    else:
        response = create_packet(status, payload)
        client_socket.sendall(response)

# Handle `REQ_CHE` – Check if username exists
def handle_check_user_exists(client_socket, users, username):
    if username in users:
        send_response(client_socket, RES_OK, "✅ Username exists.")
        return True
    else:
        send_response(client_socket, RES_ERR_NO_USER, "❌ Username not found.")
        return False

# Handle `REQ_REG` – Register a new user
def handle_reg(client_socket, users, username, password): 
    if username in users:
        send_response(client_socket, RES_ERR_USER_EXISTS, "❌ Username already exists.")
        return False

    users[username] = hash_password_sha256(password)

    # Create user’s message file
    user_message_file = os.path.join(MESSAGES_DIR, f"{username}.dat")
    with open(user_message_file, "w") as f:
        f.write("")

    send_response(client_socket, RES_OK, "✅ Registration successful.")
    return True

# Handle `REQ_LOG` – Login request
def handle_log(client_socket, users, username, password): 
    if username in users and verify_password(users[username], password):
        send_response(client_socket, RES_OK, "✅ Login successful.")
        return True
    send_response(client_socket, RES_ERR_LOGIN, "❌ Invalid credentials.")
    return False

# Handle `REQ_SET` – Save (send) a message from `username` to `target_user`
def handle_set(client_socket, users, username, message, target_user):
    if username not in users or target_user not in users:
        if client_socket:
            send_response(client_socket, RES_ERR_LOGIN, "❌ Authentication failed.")
        return

    user_message_file = os.path.join(MESSAGES_DIR, f"{username}.dat")
    target_message_file = os.path.join(MESSAGES_DIR, f"{target_user}.dat")

    entry_sender = f"SENT, {message}, {target_user}"
    entry_receiver = f"UNREAD, {message}, {username}"

    sender_lines = []
    receiver_lines = []

    if os.path.exists(user_message_file):
        with open(user_message_file, "r") as f:
            sender_lines = f.read().splitlines()
    if os.path.exists(target_message_file):
        with open(target_message_file, "r") as f:
            receiver_lines = f.read().splitlines()

    if entry_sender not in sender_lines:
        with open(user_message_file, "a") as f:
            f.write(entry_sender + "\n")
    if entry_receiver not in receiver_lines:
        with open(target_message_file, "a") as f:
            f.write(entry_receiver + "\n")

    if client_socket:
        send_response(client_socket, RES_OK, "✅ Message updated successfully.")

# Handle `REQ_UPA` – Mark all unread messages as read
def handle_update(client_socket, users, username):
    if username not in users:
        send_response(client_socket, RES_ERR_LOGIN, "❌ Authentication failed.")
        return
    user_message_file = os.path.join(MESSAGES_DIR, f"{username}.dat")
    if os.path.exists(user_message_file):
        with open(user_message_file, "r") as f:
            lines = f.readlines()
        with open(user_message_file, "w") as f:
            for line in lines:
                f.write(line.replace("UNREAD", "READ"))
    send_response(client_socket, RES_OK, "✅ User data updated successfully.")

# Handle `REQ_GET` – Retrieve messages for a user
def handle_get(client_socket, users, username): 
    if username not in users:
        send_response(client_socket, RES_ERR_LOGIN, "❌ Authentication failed.")
        return

    user_message_file = os.path.join(MESSAGES_DIR, f"{username}.dat")
    if not os.path.exists(user_message_file):
        send_response(client_socket, RES_ERR_NO_DATA, "❌ No message data found.")
        return

    with open(user_message_file, "r") as f:
        lines = f.readlines()

    # Deduplicate while preserving order
    seen = set()
    unique_lines = []
    for line in lines:
        clean = line.strip()
        if clean not in seen:
            seen.add(clean)
            unique_lines.append(clean)

    response_data = "\n".join(unique_lines)
    send_response(client_socket, RES_OK, response_data)

# Handle `REQ_DME` – Delete a message by index
def handle_delemsg(client_socket, users, username, message_id):
    if username not in users:
        send_response(client_socket, RES_ERR_LOGIN, "❌ Authentication failed.")
        return
    user_message_file = os.path.join(MESSAGES_DIR, f"{username}.dat")
    try:
        with open(user_message_file, "r") as f:
            lines = f.readlines()
        with open(user_message_file, "w") as f:
            for i, line in enumerate(lines):
                if i != int(message_id):
                    f.write(line)
        send_response(client_socket, RES_OK, "✅ Message deleted successfully.")
    except (FileNotFoundError, ValueError, IndexError):
        send_response(client_socket, RES_ERR_NO_DATA, "❌ Message not found.")

# Handle `REQ_ALL` – Get all registered usernames
def handle_all(client_socket, users, username):
    if username not in users:
        send_response(client_socket, RES_ERR_LOGIN, "❌ Authentication failed.")
        return
    user_list = "\n".join(users.keys())
    send_response(client_socket, RES_OK, user_list)

# Handle `REQ_SAV` – Save user data to node’s own users file
def handle_sav(client_socket, users):
    if USERS_FILE is None:
        send_response(client_socket, RES_ERR_SERVER, "No user file set for this node.")
        return
    with open(USERS_FILE, "w") as f:
        json.dump(users, f)
    send_response(client_socket, RES_OK, "✅ User data saved successfully.")

# Handle `REQ_DEL` – Delete a user
def handle_delete(client_socket, users, username):
    if username not in users:
        send_response(client_socket, RES_ERR_LOGIN, "❌ Authentication failed.")
        return
    del users[username]
    with open(USERS_FILE, "w") as f:
        json.dump(users, f)
    # Delete that user’s message file
    user_message_file = os.path.join(MESSAGES_DIR, f"{username}.dat")
    if os.path.exists(user_message_file):
        os.remove(user_message_file)
    send_response(client_socket, RES_OK, "✅ User deleted successfully.")

# Handle `REQ_BYE` – Logout request
def handle_bye(client_socket, username): 
    send_response(client_socket, RES_OK, f"👋 {username} You have logged out.")
    client_socket.close()
