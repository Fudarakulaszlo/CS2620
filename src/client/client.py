"""
* File: client.py
* Author: Áron Vékássy, Karen Li

This file contains the client code for the chat application.
"""

import socket
import sys
import os
import getpass

# Add the parent directory to the module search path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.protocol import *
from requests import *

# Server Configuration
HOST = "localhost"
PORT = 9999  # Must match the server port

# Connect to the chat server
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

# Authenticate user (login/register)
def authenticate(client_socket): 
    while True:
        username = input("👤 Enter your username: ").strip()
        if not validate_length(username, LEN_UNAME, "Username"):
            continue

        # Check if username exists
        response = request_check_user_exists(client_socket, username)

        if response[0] == RES_OK.strip('\x00'):
            print("🔹 Username found. Proceeding to login...")
            while True:
                # Username exists, ask for password
                # password = getpass.getpass("🔑 Enter your password: ").strip()
                password = input("🔑 Enter your password: ").strip()
                if not validate_length(password, LEN_PASSWORD, "Password"):
                    continue
                response = request_login(client_socket, username, password)

                if response[0] == RES_OK.strip('\x00'):
                    print(f"🎉 Welcome, {username}!")
                    return username
                else:
                    print("❌ Invalid password. Try again.")

        else:
            print("🔹 Username NOT found. Registering a new account...")
            while True:
                new_username = input("👤 Enter a unique username: ").strip()
                if not validate_length(new_username, LEN_UNAME, "Username"):
                    continue
                # password = getpass.getpass("🔑 Enter a new password: ").strip()
                password = input("🔑 Enter your password: ").strip()
                if not validate_length(password, LEN_PASSWORD, "Password"):
                    continue
                response = request_register(client_socket, new_username, password)

                if response[0] == RES_OK.strip('\x00'):
                    response = request_save_users(client_socket, username, password)
                    if response[0] == RES_OK.strip('\x00'):
                        print(f"🎉 New account created for {new_username}! Please log in.")
                        username = new_username  # Set new username for login
                        break  # Proceed to login
                    else:
                        print("❌ Error saving user data. Please try again.")
                else:
                    print("❌ Username already taken. Try another.")

if __name__ == "__main__":
    # Connect to server
    client_socket = connect_to_server()

    # Authenticate user (login or register)
    username = authenticate(client_socket)

    # Main loop
    while True:
        print("\n📝 Menu:")
        break

    # Disconnect from server
    disconnect_from_server(client_socket)