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

# Send a structured response to the client
def send_response(client_socket, status, payload=""):
    response = create_packet(status, payload)
    client_socket.sendall(response)

# Handle `REQ_CHE` – Check if username exists
def handle_check_user_exists(client_socket, users, username):
    if username in users:
        send_response(client_socket, RES_OK, "✅ Username exists. Proceed to login.")
    else:
        send_response(client_socket, RES_ERR_NO_USER, "❌ Username not found. Proceed to registration.")

# Handle `REQ_ALL` – Get all registered usernames
def handle_all(client_socket, users, username, password): 
    if username not in users or not verify_password(users[username], password):
        send_response(client_socket, RES_ERR_LOGIN, "❌ Authentication failed.")
        return
    user_list = "\n".join(users.keys())
    send_response(client_socket, RES_OK, user_list)

# Handle `REQ_CPW` – Change user password
def handle_cpw(client_socket, users, username, old_password, new_password): 
    if username not in users or not verify_password(users[username], old_password):
        send_response(client_socket, RES_ERR_LOGIN, "❌ Incorrect password.")
        return
    users[username] = hash_password_sha256(new_password)
    send_response(client_socket, RES_OK, "✅ Password changed successfully.")

# Handle `REQ_SET` – Save user profile data
def handle_set(client_socket, users, username, password, profile_data): 
    if username not in users or not verify_password(users[username], password):
        send_response(client_socket, RES_ERR_LOGIN, "❌ Authentication failed.")
        return
    with open(f"{username}.profile", "w") as f:
        f.write(profile_data)
    send_response(client_socket, RES_OK, "✅ Profile updated successfully.")

# Handle `REQ_GET` – Retrieve user profile data
def handle_get(client_socket, users, username, password, target_username): 
    if username not in users or not verify_password(users[username], password):
        send_response(client_socket, RES_ERR_LOGIN, "❌ Authentication failed.")
        return
    try:
        with open(f"{target_username}.profile", "r") as f:
            profile_data = f.read()
    except FileNotFoundError:
        send_response(client_socket, RES_ERR_NO_DATA, "❌ No profile data found.")
        return
    send_response(client_socket, RES_OK, profile_data)

# Handle `REQ_REG` – Register a new user
def handle_reg(client_socket, users, username, password): 
    if username in users:
        send_response(client_socket, RES_ERR_USER_EXISTS, "❌ Username already exists.")
        return
    users[username] = hash_password_sha256(password)
    send_response(client_socket, RES_OK, "✅ Registration successful.")

# Handle `REQ_LOG` – Login request
def handle_log(client_socket, users, username, password): 
    if username in users and verify_password(users[username], password):
        send_response(client_socket, RES_OK, "✅ Login successful.")
        return True
    else:
        send_response(client_socket, RES_ERR_LOGIN, "❌ Invalid credentials.")
        return False

# Handle `REQ_BYE` – Logout request
def handle_bye(client_socket, username): 
    send_response(client_socket, RES_OK, "👋 You have logged out.")
    client_socket.close()

# Handle `REQ_SAV` – Save server data
def handle_sav(client_socket, users): 
    with open("users.dat", "w") as f:
        json.dump(users, f)
    send_response(client_socket, RES_OK, "✅ User data saved successfully.")
