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
        print("❗️ No user file found. Creating `users.dat` with a default user...")
        users = {"kakali121": hash_password_sha256("Yunlei1207~")}
        save_users(users)
    else:
        try:
            with open(USER_FILE, "r") as f:
                users = json.load(f)
        except json.JSONDecodeError:
            print("❗️ Error reading user file, resetting it.")
            users = {"kakali121": hash_password_sha256("Yunlei1207~")}
            save_users(users)

    return users

# Verify a hashed password
def verify_password(stored_password, entered_password): 
    return stored_password == hash_password_sha256(entered_password)

# Handle client authentication (login or registration)
def authenticate_client(client_socket): 
    users = load_users()

    # Receive authentication request packet
    request = client_socket.recv(BUFFER_SIZE)
    cmd, payload, status = parse_packet(request)

    if status != "OK":
        response_packet = create_packet(RES_ERR_REQ_FMT, "Invalid request format.")
        client_socket.sendall(response_packet)
        return None

    if cmd == REQ_LOG:
        username, password = payload.split("|")

        if username in users and verify_password(users[username], password):
            response_packet = create_packet(RES_OK, "✅ Login successful.")
            print(f"🔑 {username} logged in.")
            client_socket.sendall(response_packet)
            return username
        else:
            response_packet = create_packet(RES_ERR_LOGIN, "❌ Invalid credentials.")
            client_socket.sendall(response_packet)
            return None

    elif cmd == REQ_REG:  
        username, password = payload.split("|")

        if username in users:
            response_packet = create_packet(RES_ERR_USER_EXISTS, "❌ Username already exists.")
            client_socket.sendall(response_packet)
            return None

        users[username] = hash_password_sha256(password)
        save_users(users)

        response_packet = create_packet(RES_OK, "✅ Registration successful.")
        print(f"🆕 New user registered: {username}")
        client_socket.sendall(response_packet)
        return username

    else:
        response_packet = create_packet(RES_ERR_INV_CMD, "❌ Invalid command.")
        client_socket.sendall(response_packet)
        return None

# Handle client connections
def handle_client(client_socket, client_address, users):
    print(f"✅ Connected to {client_address}")

    # Receive request
    request = client_socket.recv(BUFFER_SIZE)
    cmd, payload, status = parse_packet(request)

    if status != "OK":
        response_packet = create_packet(RES_ERR_REQ_FMT, "Invalid request format.")
        client_socket.sendall(response_packet)
        return

    # Handle authentication commands
    if cmd == REQ_REG:
        username, password = payload.split("|")
        handle_reg(client_socket, users, username, password)

    elif cmd == REQ_LOG:
        username, password = payload.split("|")
        username = handle_log(client_socket, users, username, password)
        if not username:
            return

        # Continue handling commands after successful login
        while True:
            request = client_socket.recv(BUFFER_SIZE)
            cmd, payload, status = parse_packet(request)
            
            if status != "OK":
                client_socket.sendall(create_packet(RES_ERR_REQ_FMT, "Invalid request format."))
                continue

            if cmd == REQ_BYE:
                handle_bye(client_socket, username)
                break
            elif cmd == REQ_CPW:
                old_password, new_password = payload.split("|")
                handle_cpw(client_socket, users, username, old_password, new_password)
            elif cmd == REQ_SET:
                password, profile_data = payload.split("|", 1)
                handle_set(client_socket, users, username, password, profile_data)
            elif cmd == REQ_GET:
                password, target_username = payload.split("|")
                handle_get(client_socket, users, username, password, target_username)
            elif cmd == REQ_ALL:
                password = payload
                handle_all(client_socket, users, username, password)
            elif cmd == REQ_SAV:
                handle_sav(client_socket, users)
            else:
                client_socket.sendall(create_packet(RES_ERR_INV_CMD, "❌ Invalid command."))

# Main function
def main():
    args = parse_args()
    if args.usage:
        usage(sys.argv[0])
        sys.exit(0)
    if args.port == 0:
        sys.stderr.write("❌ Error: Port number must be specified using -p [port]\n")
        sys.exit(1)

    # Load existing users (creates default user if missing)
    print("🔄 Loading users from database...")
    users = load_users()  # ✅ Load users once
    print(f"📂 Loaded {len(users)} user(s) from `{USER_FILE}`.")

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
            handle_client(client_socket, client_address, users)  # ✅ Pass `users`

    except KeyboardInterrupt:
        print("\n🛑 Server shutting down.")

    finally:
        server_socket.close()

if __name__ == "__main__":
    main()