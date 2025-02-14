"""
* response.py
* Author: Áron Vékássy, Karen Li

This file handles client requests and generates structured responses 
using the custom wire protocol.
"""

import os
import sys
import json 

# Add the parent directory to the module search path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.protocol import *
from common.json_protocol import *

USERS_FILE = "common/users.dat"  # File to store user credentials
MESSAGES_DIR = os.path.join("common", "messages")
os.makedirs(MESSAGES_DIR, exist_ok=True)

# Send a structured response to the client
def send_response(client_socket, status, payload=""):
    if USE_JSON:
        if isinstance(status, bytes): status = status.decode() 
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
    if username in users: # Username already exists
        send_response(client_socket, RES_ERR_USER_EXISTS, "❌ Username already exists.")
        return False
    # Append new user to the list
    users[username] = hash_password_sha256(password)
    user_message_file = os.path.join(MESSAGES_DIR, f"{username}.dat")
    # Create a new message file for the user
    with open(user_message_file, "w") as f: f.write("")
    send_response(client_socket, RES_OK, "✅ Registration successful.")
    return True

# Handle `REQ_LOG` – Login request
def handle_log(client_socket, users, username, password): 
    if username in users and verify_password(users[username], password):
        send_response(client_socket, RES_OK, "✅ Login successful.")
        return True
    send_response(client_socket, RES_ERR_LOGIN, "❌ Invalid credentials.")
    return False

# Handle `REQ_SET` – Save user data
def handle_set(client_socket, users, username, message, target_user):
    if username not in users or target_user not in users:
        send_response(client_socket, RES_ERR_LOGIN, "❌ Authentication failed.")
        return
    # Get the message file for the users
    user_message_file = os.path.join(MESSAGES_DIR, f"{username}.dat")
    target_message_file = os.path.join(MESSAGES_DIR, f"{target_user}.dat")
    # Append sent message to sender's file
    with open(user_message_file, "a") as f:
        f.write(f"SENT, {message}, {target_user}\n")
    # Append unread message to recipient's file
    with open(target_message_file, "a") as f:
        f.write(f"UNREAD, {message}, {username}\n")
    send_response(client_socket, RES_OK, "✅ Message updated successfully.")

# Handle `REQ_UPA` – Update user data
def handle_update(client_socket, users, username):
    if username not in users:
        send_response(client_socket, RES_ERR_LOGIN, "❌ Authentication failed.")
        return
    # Get the message file for the user
    user_message_file = os.path.join(MESSAGES_DIR, f"{username}.dat")
    # Load all messages
    with open(user_message_file, "r") as f:
        lines = f.readlines()
    # Replace all unread messages with read
    with open(user_message_file, "w") as f:
        for line in lines:
            f.write(line.replace("UNREAD", "READ"))
    send_response(client_socket, RES_OK, "✅ User data updated successfully.")
    
# Handle `REQ_GET` – Retrieve user  data
def handle_get(client_socket, users, username): 
    if username not in users:
        send_response(client_socket, RES_ERR_LOGIN, "❌ Authentication failed.")
        return
    # Get the message file for the users
    user_message_file = os.path.join(MESSAGES_DIR, f"{username}.dat")
    # Load all messages
    with open(user_message_file, "r") as f:
        _data = f.read()
    send_response(client_socket, RES_OK, _data)

# Handle `REQ_DME` – Delete a message
def handle_delemsg(client_socket, users, username, message_id):
    if username not in users:
        send_response(client_socket, RES_ERR_LOGIN, "❌ Authentication failed.")
        return
    # Get the message file for the users
    user_message_file = os.path.join(MESSAGES_DIR, f"{username}.dat")
    try:
        # Load all messages
        with open(user_message_file, "r") as f:
            lines = f.readlines()
        # Write all messages except the one to be deleted
        with open(user_message_file, "w") as f:
            for i, line in enumerate(lines):
                if i != int(message_id): f.write(line)     
        send_response(client_socket, RES_OK, "✅ Message deleted successfully.")
    except (FileNotFoundError, ValueError, IndexError):
        send_response(client_socket, RES_ERR_NO_DATA, "❌ Message not found.")

# Handle `REQ_ALL` – Get all registered usernames
def handle_all(client_socket, users, username):
    if username not in users:
        send_response(client_socket, RES_ERR_LOGIN, "❌ Authentication failed.")
        return
    # Get all usernames in a string
    user_list = "\n".join(users.keys())
    send_response(client_socket, RES_OK, user_list)

# Handle `REQ_SAV` – Save server data
def handle_sav(client_socket, users): 
    # Save all users to the file
    with open(USERS_FILE, "w") as f: json.dump(users, f)
    send_response(client_socket, RES_OK, "✅ User data saved successfully.")

def handle_delete(client_socket, users, username):
    if username not in users:
        send_response(client_socket, RES_ERR_LOGIN, "❌ Authentication failed.")
        return
    # Remove user from the list
    del users[username]
    # Save all users to the file
    with open(USERS_FILE, "w") as f: json.dump(users, f)
    # Delete the user's message file
    user_message_file = os.path.join(MESSAGES_DIR, f"{username}.dat")
    os.remove(user_message_file)
    send_response(client_socket, RES_OK, "✅ User deleted successfully.")

# Handle `REQ_BYE` – Logout request
def handle_bye(client_socket, username): 
    send_response(client_socket, RES_OK, f"👋 {username} You have logged out.")
    client_socket.close()