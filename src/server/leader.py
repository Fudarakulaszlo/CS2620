"""
* File: leader.py
* Author: Áron Vékássy, Karen Li

This is the leader server for the replicated chat application. It handles client connections
and replicates all write operations to follower replicas to ensure 2-fault tolerance.
"""

import socket
import argparse
import os
import sys
import json
import threading

dynamic_replicas = []  # New replicas added at runtime
replica_lock = threading.Lock()

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.protocol import *
from responses import *
from log_util import append_to_log

# Load replica configuration
def load_config(path):
    with open(path, "r") as f:
        return json.load(f)

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

# Replicate write operations to followers
def replicate_to_followers(payload, command, replicas):
    ack_count = 0
    all_replicas = replicas + dynamic_replicas
    for replica in all_replicas:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((replica['host'], replica['port']))
            s.sendall(create_packet(command, payload))
            response = s.recv(BUFFER_SIZE)
            _, _, status = parse_packet(response)
            if status == RES_OK:
                ack_count += 1
        except Exception as e:
            print(f"⚠️ Replication to {replica['host']}:{replica['port']} failed: {e}")
        finally:
            s.close()
    return ack_count >= 2

# Handle each connected client
def handle_client(client_socket, client_address, users, replicas, log_path):
    print(f"✅ Connected to {client_address}")
    try:
        while True:
            request = client_socket.recv(BUFFER_SIZE)
            if not request:
                print(f"🚫 Client {client_address} disconnected.")
                break

            cmd, payload, status = parse_packet(request)
            print(f"📩 Parsed Command: {cmd}, Payload: {payload}, Status: {status}")

            if status != RES_OK and status != 'OK':
                print("❌ Error parsing packet. Sending error response.")
                client_socket.sendall(create_packet(RES_ERR_REQ_FMT, "Invalid request."))
                continue
            if cmd == REQ_JOI:
                try:
                    ip, port = payload.split(":")
                    new_replica = {"host": ip, "port": int(port)}
                    with replica_lock:
                        if new_replica not in dynamic_replicas:
                            dynamic_replicas.append(new_replica)
                    print(f"➕ Added new replica: {new_replica}")
                    client_socket.sendall(create_packet(RES_OK, "Replica added."))
                except:
                    client_socket.sendall(create_packet(RES_ERR_REQ_FMT, "Invalid join request."))
                return
            if cmd == REQ_BYE:
                handle_bye(client_socket, payload)
                break

            # Replicated commands
            if cmd in [REQ_REG, REQ_SET, REQ_DEL, REQ_UPA, REQ_DME]: # Register, Set, Delete
                if replicate_to_followers(payload, cmd, replicas): # Replicate to followers
                    append_to_log(log_path, cmd, payload)
                    if cmd == REQ_REG: # Register new user
                        username, password = payload.split("|")
                        print(f"📝 Registering user: {username}")
                        reg_success = handle_reg(client_socket, users, username, password)
                        if reg_success: print(f"✅ User {username} registered successfully.")
                        else: print(f"❌ Error registering user {username}.")
                    elif cmd == REQ_SET: # Send receive message
                        username, message, target_user = payload.split("|")
                        handle_set(client_socket, users, username, message, target_user)
                    elif cmd == REQ_DEL:  # Delete user
                        username = payload
                        print(f"🚫 Deleting user: {username}")
                        handle_delete(client_socket, users, username)
                    elif cmd == REQ_UPA: # Update message status
                        username = payload
                        handle_update(client_socket, users, username)
                    elif cmd == REQ_DME: # Delete a message
                        username, message_id = payload.split("|")
                        handle_delemsg(client_socket, users, username, message_id) 
                else: # If replication fails, send error response
                    client_socket.sendall(create_packet(RES_ERR_SERVER, "Replication failed."))
            # Read-only operations
            elif cmd == REQ_CHE: # Check user existence
                username = payload
                print(f"🔍 Checking if user exists: {username}")
                user_exist = handle_check_user_exists(client_socket, users, username)
                if user_exist: print(f"✅ User {username} exists.")
                else: print(f"❌ User {username} does not exist.")
            elif cmd == REQ_LOG: # Login existing user
                username, password = payload.split("|")
                print(f"🔑 Logging in user: {username}")
                login_success = handle_log(client_socket, users, username, password) 
                if login_success == True: print("✅ User Login Success") 
                else: print("❌ User Login failed.") 
            elif cmd == REQ_GET: # Get user all messages
                username = payload
                handle_get(client_socket, users, username)
            elif cmd == REQ_ALL: # Get all users
                password = payload
                handle_all(client_socket, users, username)
            elif cmd == REQ_SAV: # Save user data
                username = payload 
                print(f"💾 Saving server data for {username}")
                handle_sav(client_socket, users)
            else:
                print(f"❌ Unknown command: {cmd}")
                client_socket.sendall(create_packet(RES_ERR_INV_CMD, "Unknown command."))
    except Exception as e:
        print(f"❌ Error handling {client_address}: {e}")
    finally:
        client_socket.close()
        print(f"🔻 Disconnected {client_address}")

# Start the leader server
def start_leader(config_path):
    config = load_config(config_path)
    port = config["port"]
    replicas = config["replicas"]
    log_path = config.get("log", "common/logs/leader.log")
    users = load_users()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", port))
    server_socket.listen(25)

    print(f"🚀 Leader running on port {port}, replicating to {len(replicas)} replicas")
    while True:
        client_socket, client_address = server_socket.accept()
        threading.Thread(target=handle_client, args=(client_socket, client_address, users, replicas, log_path), daemon=True).start()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, help="Path to leader config file")
    args = parser.parse_args()
    start_leader(args.config)
