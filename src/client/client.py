'''
* File: client.py
* Author: Áron Vékássy, Karen Li

This file contains the client code for the chat application.
'''

import socket
import argparse
import sys
import json
import getpass

# Server Configurations
BUFFER_SIZE = 1024

# Server Configuration
HOST = "localhost"  # Change if server is on another machine
PORT = 5050         # Must match the server port

# class ClientArgs:
#     """Stores command-line arguments for the client."""
#     def __init__(self):
#         self.server = ""   # Server IP or hostname
#         self.port = 0      # Server port
#         self.username = "" # Username for authentication
#         self.password = "" # User password
#         self.command = ""  # Command to execute
#         self.arg1 = ""     # First argument (if needed)
#         self.arg2 = ""     # Second argument (if needed)

# Connects to the chat server and verifies the connection
def connect_to_server():
    try:
        # Create a TCP socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
        # Connect to the server
        client_socket.connect((HOST, PORT))
        print(f"✅ Connected to server at {HOST}:{PORT}")

        # Close the socket
        client_socket.close()
        print("❌ Disconnected from server.")

    except ConnectionRefusedError:
        print(f"❌ Connection failed! Is the server running on {HOST}:{PORT}?")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    connect_to_server()