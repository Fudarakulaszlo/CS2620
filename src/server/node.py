#!/usr/bin/env python3
"""
node.py - Unified chat server node with leader election, persistent logging,
replication, and dynamic membership (including join requests).

Usage:
    python3 server/node.py --id <node_id> --host <host_ip> --port <port> --membership <membership.json>

The membership file is a JSON array of node info dictionaries, e.g.:
[
    {"id": 1, "host": "127.0.0.1", "port": 9001},
    {"id": 2, "host": "127.0.0.1", "port": 9002},
    {"id": 3, "host": "127.0.0.1", "port": 9003}
]
"""

import socket
import threading
import time
import json
import os
import sys
import argparse

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.protocol import *    # Now includes REQ_ELEC, RES_OK_ELEC, REQ_COORD, REQ_HRTBT, REQ_JOIN, RES_JOIN
from responses import *          # Handlers: handle_reg, handle_set, handle_delete, etc.
from log_util import append_to_log, replay_log

# Global state for this node (set during startup)
NODE_ROLE = "FOLLOWER"     # "LEADER" or "FOLLOWER"
LEADER_INFO = None         # Dict: {"id": <int>, "host": <str>, "port": <int>}
MEMBERSHIP = []            # List of all nodes, each dict has keys: id, host, port
NODE_ID = None             # Unique id for this node (int)
MY_HOST = None             # This node's host IP
MY_PORT = None             # This node's port

# Constants for heartbeat and election timeouts
HEARTBEAT_INTERVAL = 2     # Leader sends heartbeat every 2 seconds
HEARTBEAT_TIMEOUT = 5      # Followers wait 5 seconds for a heartbeat

# Global variable to track the last heartbeat time (updated upon receiving a heartbeat)
LAST_HB = time.time()

# --- Helper functions ---

def send_packet(target, packet):
    """Send a packet to a target node and return its response (if any)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target['host'], target['port']))
        s.sendall(packet)
        response = s.recv(BUFFER_SIZE)
        s.close()
        return response
    except Exception as e:
        return None

def send_heartbeat():
    """If leader, periodically send heartbeat messages to all other nodes."""
    while NODE_ROLE == "LEADER":
        for node in MEMBERSHIP:
            if node['id'] == NODE_ID:
                continue
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((node['host'], node['port']))
                pkt = create_packet(REQ_HRTBT, str(NODE_ID))
                s.sendall(pkt)
                s.close()
            except Exception:
                pass
        time.sleep(HEARTBEAT_INTERVAL)

def election_listener(conn):
    """
    Handle an incoming packet that may be an election-related message.
    """
    global NODE_ROLE, LEADER_INFO, LAST_HB
    try:
        packet = conn.recv(BUFFER_SIZE)
        if not packet:
            return
        cmd, payload, status = parse_packet(packet)
        if cmd == REQ_HRTBT:
            LAST_HB = time.time()
            leader_id = int(payload)
            for node in MEMBERSHIP:
                if node['id'] == leader_id:
                    LEADER_INFO = node
                    break
        elif cmd == REQ_ELEC:
            sender_id = int(payload)
            if NODE_ID > sender_id:
                conn.sendall(create_packet(RES_OK_ELEC, ""))
                threading.Thread(target=initiate_election, daemon=True).start()
        elif cmd == REQ_COORD:
            leader_id = int(payload)
            for node in MEMBERSHIP:
                if node['id'] == leader_id:
                    LEADER_INFO = node
                    break
            NODE_ROLE = "FOLLOWER"
            print(f"[Election Listener] New leader announced: {LEADER_INFO}", flush=True)
        else:
            print(f"[Election Listener] Received non-election message: {cmd}", flush=True)
    except Exception as e:
        print(f"[Election Listener] Error: {e}", flush=True)
    finally:
        conn.close()

def initiate_election():
    """
    Initiate an election by sending an election message to all nodes with higher IDs.
    If no higher-priority node responds, become leader and broadcast coordinator message.
    """
    global NODE_ROLE, LEADER_INFO
    print("[Election] Initiating election...", flush=True)
    responses_received = 0
    for node in MEMBERSHIP:
        if node['id'] > NODE_ID:
            try:
                response = send_packet(node, create_packet(REQ_ELEC, str(NODE_ID)))
                if response:
                    r_cmd, _, r_status = parse_packet(response)
                    if r_cmd == RES_OK_ELEC:
                        responses_received += 1
                        print(f"[Election] Received election OK from node {node['id']}", flush=True)
            except Exception:
                continue

    if responses_received == 0:
        NODE_ROLE = "LEADER"
        LEADER_INFO = {"id": NODE_ID, "host": MY_HOST, "port": MY_PORT}
        print(f"[Election] I am the new leader! Node {NODE_ID} assuming leadership.", flush=True)
        for node in MEMBERSHIP:
            if node['id'] == NODE_ID:
                continue
            try:
                send_packet(node, create_packet(REQ_COORD, str(NODE_ID)))
                print(f"[Election] Sent coordinator message to node {node['id']}", flush=True)
            except Exception:
                continue
        threading.Thread(target=send_heartbeat, daemon=True).start()
    else:
        timeout = HEARTBEAT_TIMEOUT
        waited = 0
        while waited < timeout and LEADER_INFO is None:
            time.sleep(1)
            waited += 1
        if LEADER_INFO is None:
            NODE_ROLE = "LEADER"
            LEADER_INFO = {"id": NODE_ID, "host": MY_HOST, "port": MY_PORT}
            print("[Election] Timeout waiting for coordinator. Becoming leader.", flush=True)
            for node in MEMBERSHIP:
                if node['id'] == NODE_ID:
                    continue
                try:
                    send_packet(node, create_packet(REQ_COORD, str(NODE_ID)))
                    print(f"[Election] Sent coordinator message to node {node['id']}", flush=True)
                except Exception:
                    continue
            threading.Thread(target=send_heartbeat, daemon=True).start()
    print(f"[Election] Election completed. Current leader: {LEADER_INFO}", flush=True)

def election_monitor():
    """
    In follower mode, monitor for heartbeats.
    If a heartbeat is not received within the timeout period, initiate an election.
    """
    global LAST_HB
    while True:
        if NODE_ROLE == "FOLLOWER":
            elapsed = time.time() - LAST_HB
            if elapsed > HEARTBEAT_TIMEOUT:
                print(f"[Monitor] Heartbeat timeout (elapsed {elapsed:.2f}s). Starting election.", flush=True)
                initiate_election()
                LAST_HB = time.time()  # Reset timestamp after initiating election.
        time.sleep(1)

# --- Join Request Handling ---

def handle_join(conn, data, log_path):
    global MEMBERSHIP, LEADER_INFO
    if NODE_ROLE == "LEADER":
        try:
            ip, port_str = data.split(":")
            port = int(port_str)
        except Exception as e:
            send_response(conn, RES_ERR_REQ_FMT, "Invalid join format. Expected ip:port")
            return

        for node in MEMBERSHIP:
            if node['host'] == ip and node['port'] == port:
                join_info = json.dumps({"id": node["id"], "membership": MEMBERSHIP})
                send_response(conn, RES_JOIN, join_info)
                return

        new_id = max(node['id'] for node in MEMBERSHIP) + 1 if MEMBERSHIP else 1
        new_node = {"id": new_id, "host": ip, "port": port}
        MEMBERSHIP.append(new_node)
        append_to_log(log_path, REQ_JOIN, f"{ip}:{port}|{new_id}")
        join_info = json.dumps({"id": new_id, "membership": MEMBERSHIP})
        send_response(conn, RES_JOIN, join_info)
        print(f"[Join] New node joined: {new_node}", flush=True)
    else:
        if LEADER_INFO:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((LEADER_INFO['host'], LEADER_INFO['port']))
                s.sendall(create_packet(REQ_JOIN, data))
                response = s.recv(BUFFER_SIZE)
                conn.sendall(response)
                s.close()
                print("[Join] Forwarded join request to leader.", flush=True)
            except Exception as e:
                send_response(conn, RES_ERR_SERVER, "Leader unreachable.")
        else:
            send_response(conn, RES_ERR_SERVER, "No leader elected.")

# --- End Join Handling ---

def client_handler(conn, client_address, users, log_path):
    # Set a timeout so that if no new data arrives, we don't break the loop.
    conn.settimeout(10)
    try:
        while True:
            try:
                data = conn.recv(BUFFER_SIZE)
            except socket.timeout:
                # No data received in 10 seconds, continue waiting
                continue
            if not data:
                break
            try:
                cmd, payload, status = parse_packet(data)
            except Exception as e:
                continue

            if cmd == REQ_JOIN:
                handle_join(conn, payload, log_path)
                continue

            if cmd in [REQ_REG, REQ_SET, REQ_DEL, REQ_UPA, REQ_DME]:
                if NODE_ROLE == "LEADER":
                    acks = 0
                    for node in MEMBERSHIP:
                        if node['id'] == NODE_ID:
                            continue
                        try:
                            resp = send_packet(node, create_packet(cmd, payload))
                            if resp:
                                _, _, r_status = parse_packet(resp)
                                if r_status == RES_OK:
                                    acks += 1
                        except Exception as e:
                            print(f"[Replication] Node {node['id']} unreachable: {e}", flush=True)
                    append_to_log(log_path, cmd, payload)
                    if cmd == REQ_REG:
                        username, password = payload.split("|")
                        handle_reg(conn, users, username, password)
                    elif cmd == REQ_SET:
                        username, message, target = payload.split("|")
                        handle_set(conn, users, username, message, target)
                    elif cmd == REQ_DEL:
                        handle_delete(conn, users, payload)
                    elif cmd == REQ_UPA:
                        handle_update(conn, users, payload)
                    elif cmd == REQ_DME:
                        username, msg_id = payload.split("|")
                        handle_delemsg(conn, users, username, msg_id)
                else:
                    if LEADER_INFO:
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.connect((LEADER_INFO['host'], LEADER_INFO['port']))
                            s.sendall(data)
                            response = s.recv(BUFFER_SIZE)
                            conn.sendall(response)
                            s.close()
                        except Exception as e:
                            send_response(conn, RES_ERR_SERVER, "Leader unreachable.")
                    else:
                        send_response(conn, RES_ERR_SERVER, "No leader elected.")
            else:
                if cmd == REQ_CHE:
                    handle_check_user_exists(conn, users, payload)
                elif cmd == REQ_LOG:
                    username, password = payload.split("|")
                    handle_log(conn, users, username, password)
                elif cmd == REQ_GET:
                    handle_get(conn, users, payload)
                elif cmd == REQ_ALL:
                    handle_all(conn, users, payload)
                elif cmd == REQ_SAV:
                    handle_sav(conn, users)
                elif cmd == REQ_BYE:
                    handle_bye(conn, payload)
                    break
                else:
                    send_response(conn, RES_ERR_INV_CMD, "Unknown command.")
    except Exception as e:
        print(f"[Client Handler] Error: {e}", flush=True)
    finally:
        conn.close()

def handle_connection(conn, addr, users, log_path):
    try:
        data = conn.recv(BUFFER_SIZE, socket.MSG_PEEK)
        if not data:
            conn.close()
            return
        cmd_field = data[2:10]
        election_cmds = [REQ_ELEC, REQ_COORD, REQ_HRTBT]
        if cmd_field in election_cmds:
            election_listener(conn)
        else:
            print(f"[Server] Received client connection from {addr}", flush=True)
            client_handler(conn, addr, users, log_path)
    except Exception as e:
        print(f"[Connection Handler] Error: {e}", flush=True)
        conn.close()

def load_users():
    from responses import USERS_FILE, MESSAGES_DIR
    import json
    if not os.path.exists(USERS_FILE):
        print("❗ No user file found. Creating default user.", flush=True)
        from common.protocol import hash_password_sha256
        default_hash = hash_password_sha256("Yunlei1207~")
        users = {"kakali121": default_hash}
        with open(USERS_FILE, "w") as f:
            json.dump(users, f)
        user_message_file = os.path.join(MESSAGES_DIR, "kakali121.dat")
        with open(user_message_file, "w") as f:
            f.write("")
    else:
        try:
            with open(USERS_FILE, "r") as f:
                users = json.load(f)
        except Exception as e:
            print("❗ Error reading user file; resetting.", flush=True)
            from common.protocol import hash_password_sha256
            default_hash = hash_password_sha256("Yunlei1207~")
            users = {"kakali121": default_hash}
            with open(USERS_FILE, "w") as f:
                json.dump(users, f)
            user_message_file = os.path.join("common", "messages", "kakali121.dat")
            with open(user_message_file, "w") as f:
                f.write("")
    return users

def node_server():
    users = load_users()
    log_path = f"common/logs/node_{NODE_ID}.log"
    
    entries = replay_log(log_path)
    for entry in entries:
        cmd, payload = entry["cmd"], entry["payload"]
        if cmd == "REQ_REG":
            username, password = payload.split("|")
            handle_reg(None, users, username, password)
        elif cmd == "REQ_SET":
            username, message, target = payload.split("|")
            handle_set(None, users, username, message, target)
        elif cmd == "REQ_DEL":
            handle_delete(None, users, payload)
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((MY_HOST, MY_PORT))
    server_socket.listen(25)
    print(f"[Node {NODE_ID}] Listening on {MY_HOST}:{MY_PORT} as {NODE_ROLE}", flush=True)

    while True:
        try:
            conn, addr = server_socket.accept()
            print(f"[Server] Accepted connection from {addr}", flush=True)
            threading.Thread(target=handle_connection, args=(conn, addr, users, log_path), daemon=True).start()
        except Exception as e:
            print(f"[Server] Error accepting connection: {e}", flush=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", type=int, required=True, help="Unique node ID (integer)")
    parser.add_argument("--host", required=True, help="Host IP")
    parser.add_argument("--port", type=int, required=True, help="Port number")
    parser.add_argument("--membership", required=True, help="Path to JSON membership file")
    args = parser.parse_args()

    NODE_ID = args.id
    MY_HOST = args.host
    MY_PORT = args.port
    try:
        with open(args.membership, "r") as f:
            MEMBERSHIP = json.load(f)
    except Exception as e:
        print("Error loading membership file:", e, flush=True)
        sys.exit(1)

    leader_candidate = max(MEMBERSHIP, key=lambda x: x["id"])
    if leader_candidate["id"] == NODE_ID:
        NODE_ROLE = "LEADER"
        LEADER_INFO = {"id": NODE_ID, "host": MY_HOST, "port": MY_PORT}
        threading.Thread(target=send_heartbeat, daemon=True).start()
    else:
        NODE_ROLE = "FOLLOWER"
        LEADER_INFO = leader_candidate

    if NODE_ROLE == "FOLLOWER":
        threading.Thread(target=election_monitor, daemon=True).start()

    print(f"[Startup] Node {NODE_ID} starting as {NODE_ROLE}. Current leader: {LEADER_INFO}", flush=True)
    node_server()
