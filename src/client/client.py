"""
* File: client.py
* Author: Áron Vékássy, Karen Li

This file contains the client code for the chat application.
"""

import socket
import argparse
import os
import sys
import json
import getpass
import hashlib

# Add the parent directory to the module search path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.protocol import *

# Server Configuration
HOST = "localhost"
PORT = 9999  # Must match the server port

# Connects to the chat server
def connect_to_server(): 
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((HOST, PORT))
        print(f"✅ Connected to server at {HOST}:{PORT}")
        return client_socket
    except ConnectionRefusedError:
        print(f"❌ Connection failed! Is the server running on {HOST}:{PORT}?")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

# Disconnect from the server
def disconnect_from_server(client_socket):
    try:
        client_socket.close()
        print("🚫 Disconnected from server.")
    except Exception as e:
        print(f"❌ Error disconnecting from server: {e}")

# Send a message to the server and receive a response
def send_packet(client_socket, packet): 
    client_socket.sendall(packet)
    response = client_socket.recv(BUFFER_SIZE)
    print(f"📩 Client Received Raw Packet: {response}")  # Debugging print
    return parse_packet(response)

# Handle user authentication (login/register)
def authenticate(client_socket):
    username = input("Enter your username: ").strip()

    # Send login request
    packet = create_packet(REQ_LOG, username)
    response_cmd, response_payload, status = send_packet(client_socket, packet)

    if status != "OK":
        print("❌ Error: Invalid response format.")
        return None

    if response_cmd == RES_ERR_NO_USER:
        # New user → Register
        print("🔹 Username not found. Registering new user...")
        password = getpass.getpass("Enter a new password: ").strip()
        hashed_password = hash_password_sha256(password)
        packet = create_packet(REQ_REG, f"{username}|{hashed_password}")
        response_cmd, response_payload, status = send_packet(client_socket, packet)
        
        print(response_payload)
        return username if response_cmd == RES_OK else None

    elif response_cmd == RES_OK:
        # Existing user → Login
        password = getpass.getpass("Enter your password: ").strip()
        hashed_password = hash_password_sha256(password)
        packet = create_packet(REQ_LOG, f"{username}|{hashed_password}")
        response_cmd, response_payload, status = send_packet(client_socket, packet)

        print(response_payload)
        return username if response_cmd == RES_OK else None

    return None

if __name__ == "__main__":
    # Connect to server
    client_socket = connect_to_server()

    # Authenticate user
    username = authenticate(client_socket)
    if not username:
        print("❌ Authentication failed. Exiting...")
        disconnect_from_server(client_socket)
        sys.exit(1)

    print(f"🎉 Welcome, {username}!")

    # Disconnect from server
    disconnect_from_server(client_socket)