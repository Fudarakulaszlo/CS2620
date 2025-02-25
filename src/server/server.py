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
import threading

# Add the parent directory to the module search path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.protocol import *
from responses import *

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

# Load stored usernames & passwords
def load_users():
    if not os.path.exists(USERS_FILE): 
        print("❗ No user found. Creating a default user.")
        hash_psw = hash_password_sha256("Yunlei1207~")
        users = {"kakali121": hash_psw}
        # Save one user to file
        with open(USERS_FILE, "w") as f: json.dump(users, f)
        # Create a message file for the user
        user_message_file = os.path.join(MESSAGES_DIR, "kakali121.dat")
        # Create a new message file for the user
        with open(user_message_file, "w") as f: f.write("")
    else: # Load existing users
        try:
            with open(USERS_FILE, "r") as f: users = json.load(f)
        except json.JSONDecodeError:
            print("❗ Error reading user file, resetting it.")
            hash_psw = hash_password_sha256("Yunlei1207~")
            users = {"kakali121": hash_psw}
            with open(USERS_FILE, "w") as f: json.dump(users, f)
            # Create a message file for the user
            user_message_file = os.path.join(MESSAGES_DIR, "kakali121.dat")
            # Create a new message file for the user
            with open(user_message_file, "w") as f: f.write("")
    return users

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

            # Use JSON protocol if enabled
            if USE_JSON:
                request_str = request.decode()
                cmd, payload, status = parse_json(request_str)
                # mkae cmd and status bytes
                cmd = cmd.encode()
            else:
                cmd, payload, status = parse_packet(request)
            print(f"📩 Parsed Command: {cmd}, Payload: {payload}, Status: {status}")

            if status != RES_OK and status != 'OK':
                print("❌ Error parsing packet. Sending error response.")
                client_socket.sendall(create_packet(RES_ERR_REQ_FMT, "Invalid request format."))
                continue
            
            if cmd == REQ_BYE:
                handle_bye(client_socket, username)
                break
            # Handle authentication commands
            if cmd == REQ_CHE: # Check existing user
                username = payload
                print(f"🔍 Checking if user exists: {username}")
                user_exist = handle_check_user_exists(client_socket, users, username)
                if user_exist: print(f"✅ User {username} exists.")
                else: print(f"❌ User {username} does not exist.")
            elif cmd == REQ_REG: # Register new user
                username, password = payload.split("|")
                print(f"📝 Registering user: {username}")
                reg_success = handle_reg(client_socket, users, username, password)
                if reg_success: print(f"✅ User {username} registered successfully.")
                else: print(f"❌ Error registering user {username}.")
            elif cmd == REQ_LOG: # Login existing user
                username, password = payload.split("|")
                print(f"🔑 Logging in user: {username}")
                login_success = handle_log(client_socket, users, username, password) 
                if login_success == True: print("✅ User Login Success") 
                else: print("❌ User Login failed.") 
            elif cmd == REQ_SET: # Send receive message
                username, message, target_user = payload.split("|")
                handle_set(client_socket, users, username, message, target_user)
            elif cmd == REQ_UPA: # Update message status
                username = payload
                handle_update(client_socket, users, username)
            elif cmd == REQ_GET: # Get user all messages
                username = payload
                handle_get(client_socket, users, username)
            elif cmd == REQ_DME: # Delete a message
                username, message_id = payload.split("|")
                handle_delemsg(client_socket, users, username, message_id) 
            elif cmd == REQ_ALL: # Get all users
                password = payload
                handle_all(client_socket, users, username)
            elif cmd == REQ_SAV: # Save user data
                username = payload 
                print(f"💾 Saving server data for {username}")
                handle_sav(client_socket, users)
            elif cmd == REQ_DEL: # Delete user
                username = payload
                print(f"🚫 Deleting user: {username}")
                handle_delete(client_socket, users, username)
            else: # Unknown command
                print(f"❌ Unknown command {cmd}. Sending error response.")
    except Exception as e:   
        print(f"❌ Error handling {client_address}: {e}")

    finally: 
        print(f"🔻 Client {client_address} disconnected")
        client_socket.close()  # Close the client socket


# Start the server and accept client connections
def start_server(args): 
    users = load_users()
    print(f"🔐 User database loaded. {len(users)} users found.")
    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", args.port))
    server_socket.listen(500)
    print(f"🚀 Server listening on port {args.port}...")
    try:
        while True:
            print("⌛ Waiting for a client to connect...")
            client_socket, client_address = server_socket.accept()
            threading.Thread(target=handle_client, args=(client_socket, client_address, users), daemon=True).start()
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