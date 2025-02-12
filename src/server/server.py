"""
* File: server.py
* Author: Áron Vékássy, Karen Li

This file contains the server code for the chat application.
"""

import socket
import argparse
import os
import sys
import json 

# Add the parent directory to the module search path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.protocol import *
from responses import *

USER_FILE = "users.dat"  # File to store user credentials

# Server Argument Structure  
class ServerArgs:  
    def __init__(self):
        self.port = 0  # Port number
        self.usage = False  # Help flag

# Print usage instructions
def usage(progname):
    print(f"{progname}: A chat server with user authentication using a custom protocol.")
    print("  -p [int]    Port number of the server")
    print("  -h          Print help (this message)")

# Parse command-line arguments
def parse_args():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-p", type=int, help="Port number")
    parser.add_argument("-h", action="store_true", help="Print help message")

    args = parser.parse_args()
    server_args = ServerArgs()
    if args.h: server_args.usage = True
    if args.p: server_args.port = args.p
    return server_args

# Save users back to the file
def save_users(users): 
    with open(USER_FILE, "w") as f:
        json.dump(users, f)

# Load stored usernames & passwords
def load_users():
    if not os.path.exists(USER_FILE):
        print("❗ No user file found. Creating `users.dat` with a default user...")
        users = {"kakali121": hash_password_sha256("Yunlei1207~")}
        save_users(users)
    else:
        try:
            with open(USER_FILE, "r") as f:
                users = json.load(f)
        except json.JSONDecodeError:
            print("❗ Error reading user file, resetting it.")
            users = {"kakali121": hash_password_sha256("Yunlei1207~")}
            save_users(users)
    return users

# Verify a hashed password
def verify_password(stored_password, entered_password): 
    return stored_password == hash_password_sha256(entered_password)

# Handle client connections
def handle_client(client_socket, client_address, users):
    print(f"✅ Connected to {client_address}")

    try:
        while True:
            # Receive request
            request = client_socket.recv(BUFFER_SIZE)
            print(f"📩 Raw Packet Received from {client_address}: {request}")

            if not request:
                print(f"🚫 Client {client_address} disconnected.")
                break
            
            cmd, payload, status = parse_packet(request)
            print(f"📩 Parsed Command: {cmd}, Payload: {payload}, Status: {status}")

            if status != "OK":
                print("❌ Error parsing packet. Sending error response.")
                client_socket.sendall(create_packet(RES_ERR_REQ_FMT, "Invalid request format."))
                continue
            
            # Handle authentication commands
            if cmd == REQ_CHE.strip('\x00'):  
                print(f"🔍 Checking if user exists: {payload}")
                handle_check_user_exists(client_socket, users, payload)
            elif cmd == REQ_REG.strip('\x00'):
                username, password = payload.split("|")
                print(f"📝 Registering user: {username}")
                handle_reg(client_socket, users, username, password)
            elif cmd == REQ_LOG.strip('\x00'):
                username, password = payload.split("|")
                print(f"🔑 Logging in user: {username}")
                username = handle_log(client_socket, users, username, password)
                if not username:
                    client_socket.sendall(create_packet(RES_ERR_LOGIN, "❌ Login failed."))
                    return  
                # Continue handling commands after successful login
                while True:
                    request = client_socket.recv(BUFFER_SIZE)
                    cmd, payload, status = parse_packet(request)

                    if status != "OK":
                        client_socket.sendall(create_packet(RES_ERR_REQ_FMT, "Invalid request format."))
                        continue
                    if cmd == REQ_BYE.strip('\x00'):
                        handle_bye(client_socket, username)
                        break
                    elif cmd == REQ_CPW.strip('\x00'):
                        old_password, new_password = payload.split("|")
                        handle_cpw(client_socket, users, username, old_password, new_password)
                    elif cmd == REQ_SET.strip('\x00'):
                        password, profile_data = payload.split("|", 1)
                        handle_set(client_socket, users, username, password, profile_data)
                    elif cmd == REQ_GET.strip('\x00'):
                        password, target_username = payload.split("|")
                        handle_get(client_socket, users, username, password, target_username)
                    elif cmd == REQ_ALL.strip('\x00'):
                        password = payload
                        handle_all(client_socket, users, username, password)
                    elif cmd == REQ_SAV.strip('\x00'):
                        handle_sav(client_socket, users)
                    else:
                        client_socket.sendall(create_packet(RES_ERR_INV_CMD, "❌ Invalid command."))
    except Exception as e:   
        print(f"❌ Error handling {client_address}: {e}")
    finally:
        client_socket.close()  # Close the client socket

# Start the server and accept client connections
def start_server(args): 
    users = load_users()
    print("🔐 User database loaded.")

    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", args.port))
    server_socket.listen(25)
    print(f"🚀 Server listening on port {args.port}...")

    try:
        while True:
            print("⌛ Waiting for a client to connect...")
            client_socket, client_address = server_socket.accept()
            handle_client(client_socket, client_address, users)

    except KeyboardInterrupt:
        print("\n🛑 Server shutting down.")

    finally:
        server_socket.close()

# Main function
def main():
    args = parse_args()
    if args.usage:
        usage(sys.argv[0])
        sys.exit(0)
    if args.port == 0:
        sys.stderr.write("❌ Error: Port number must be specified using -p [port]\n")
        sys.exit(1) 
    start_server(args)

if __name__ == "__main__":
    main()