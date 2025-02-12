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

# Verify a hashed password
def verify_password(stored_password, entered_password): 
    return stored_password == hash_password_sha256(entered_password)

# Handle `REQ_CHE` – Check if username exists
def handle_check_user_exists(client_socket, users, username):
    if username in users:
        response = create_packet(RES_OK, "✅ Username exists. Proceed to login.")
    else:
        response = create_packet(RES_ERR_NO_USER, "❌ Username not found. Proceed to registration.")
    client_socket.sendall(response)

# Handle `REQ_ALL` – Get all registered usernames
def handle_all(client_socket, users, username, password): 
    if username not in users or not verify_password(users[username], password):
        response = create_packet(RES_ERR_LOGIN, "❌ Authentication failed.")
        client_socket.sendall(response)
        return
    user_list = "\n".join(users.keys())
    response = create_packet(RES_OK, user_list)
    client_socket.sendall(response)

# Handle `REQ_CPW` – Change user password
def handle_cpw(client_socket, users, username, old_password, new_password): 
    if username not in users or not verify_password(users[username], old_password):
        response = create_packet(RES_ERR_LOGIN, "❌ Incorrect password.")
        client_socket.sendall(response)
        return
    
    users[username] = hash_password_sha256(new_password)
    response = create_packet(RES_OK, "✅ Password changed successfully.")
    client_socket.sendall(response)

# Handle `REQ_SET` – Save user profile data
def handle_set(client_socket, users, username, password, profile_data): 
    if username not in users or not verify_password(users[username], password):
        response = create_packet(RES_ERR_LOGIN, "❌ Authentication failed.")
        client_socket.sendall(response)
        return
    # Save profile data to a file
    with open(f"{username}.profile", "w") as f:
        f.write(profile_data)
    response = create_packet(RES_OK, "✅ Profile updated successfully.")
    client_socket.sendall(response)

# Handle `REQ_GET` – Retrieve user profile data
def handle_get(client_socket, users, username, password, target_username): 
    if username not in users or not verify_password(users[username], password):
        response = create_packet(RES_ERR_LOGIN, "❌ Authentication failed.")
        client_socket.sendall(response)
        return
    try:
        with open(f"{target_username}.profile", "r") as f:
            profile_data = f.read()
    except FileNotFoundError:
        response = create_packet(RES_ERR_NO_DATA, "❌ No profile data found.")
        client_socket.sendall(response)
        return

    response = create_packet(RES_OK, profile_data)
    client_socket.sendall(response)

# Handle `REQ_REG` – Register a new user
def handle_reg(client_socket, users, username, password): 
    if username in users:
        response = create_packet(RES_ERR_USER_EXISTS, "❌ Username already exists.")
        client_socket.sendall(response)
        return
    users[username] = hash_password_sha256(password)
    response = create_packet(RES_OK, "✅ Registration successful.")
    client_socket.sendall(response)

# Handle `REQ_LOG` – Login request
def handle_log(client_socket, users, username, password): 
    if username in users and verify_password(users[username], password):
        response = create_packet(RES_OK, "✅ Login successful.")
        client_socket.sendall(response)
        return username
    else:
        response = create_packet(RES_ERR_LOGIN, "❌ Invalid credentials.")
        client_socket.sendall(response)
        return None

# Handle `REQ_BYE` – Logout request
def handle_bye(client_socket, username): 
    response = create_packet(RES_OK, "👋 You have logged out.")
    client_socket.sendall(response)
    client_socket.close()

# Handle `REQ_SAV` – Save server data
def handle_sav(client_socket, users): 
    with open("users.dat", "w") as f:
        json.dump(users, f)
    response = create_packet(RES_OK, "✅ User data saved successfully.")
    client_socket.sendall(response)