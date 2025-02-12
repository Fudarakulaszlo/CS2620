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
        username = input(">  Enter your username: ").strip()

        # Check if username exists
        response = send_request(client_socket, REQ_CHE, username) 

        if "Username exists" in response:
            # Username exists, ask for password
            password = getpass.getpass("Enter your password: ").strip()
            response = request_login(client_socket, username, password)

            if "Login successful" in response:
                print(f"🎉 Welcome, {username}!")
                return username
            else:
                print("❌ Invalid password. Try again.")

        elif "Username not found" in response:
            # Username does not exist, prompt to register
            print("🔹 Username not found. Registering a new account...")
            while True:
                new_username = input("Enter a unique username: ").strip()
                password = getpass.getpass("Enter a new password: ").strip()
                response = request_register(client_socket, new_username, password)

                if "Username already taken" in response:
                    print("❌ Username already taken. Try another.")
                else:
                    print("✅ Registration successful. Please log in.")
                    username = new_username  # Set new username for login
                    break  # Proceed to login

if __name__ == "__main__":
    # Connect to server
    client_socket = connect_to_server()

    # Authenticate user (login or register)
    username = authenticate(client_socket)

    # Disconnect from server
    disconnect_from_server(client_socket)