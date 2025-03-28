#!/usr/bin/env python3
"""
node.py - Unified chat server node with leader election, replication,
dynamic membership, local membership files, and post-startup data + membership pull.

Usage:
    python3 node.py --id <node_id> --host <host_ip> --port <port> --membership <some_initial.json>
"""

import socket
import threading
import time
import json
import os
import sys
import argparse

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from common.protocol import (
    BUFFER_SIZE, create_packet, parse_packet,
    REQ_ELEC, RES_OK_ELEC, REQ_COORD, REQ_HRTBT,
    REQ_JOIN, RES_JOIN,
    REQ_PULL, RES_PULL,
    REQ_REG, REQ_SET, REQ_DEL, REQ_UPA, REQ_DME,
    REQ_CHE, REQ_LOG, REQ_GET, REQ_ALL, REQ_SAV, REQ_BYE,
    RES_OK, RES_ERR_SERVER, RES_ERR_INV_CMD, RES_ERR_REQ_FMT,
    hash_password_sha256
)
from responses import (
    set_node_id,
    handle_reg, handle_set, handle_delete, handle_update, handle_delemsg,
    handle_check_user_exists, handle_log, handle_get, handle_all, handle_sav, handle_bye,
    send_response, USERS_FILE
)
from log_util import append_to_log, replay_log

# ---------------------------------------
# Additional membership fetch commands
# (You add these to protocol.py if not present)
# ---------------------------------------
REQ_MEM = b"REQ_MEM__"  # Client (or node) requests current membership from the leader
RES_MEM = b"MEM_OK___"  # Leader responds with membership JSON

# ---------------------------------------
# Membership update command (Leader -> Followers)
# ---------------------------------------
REQ_MUP = b"MUPDT___"
"""
REQ_MUP: membership update broadcast from leader to followers
whenever membership changes (like a new node joining).
"""

# ------------------------------------------------------------------------------
# Global node state
# ------------------------------------------------------------------------------
NODE_ROLE = "FOLLOWER"  # "LEADER" or "FOLLOWER"
LEADER_INFO = None
MEMBERSHIP = []         # in-memory membership
NODE_ID = None
MY_HOST = None
MY_PORT = None

HEARTBEAT_INTERVAL = 2
HEARTBEAT_TIMEOUT = 5
LAST_HB = time.time()

EVENTS_LOG_PATH = None
LOCAL_MEMBERSHIP_FILE = None

# We'll store the node's user dictionary in global_users
global_users = {}

def log_event(msg):
    """
    Append a timestamped message to node_{NODE_ID}_events.log
    for major events, so we avoid spamming the console.
    """
    if not EVENTS_LOG_PATH:
        return
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    with open(EVENTS_LOG_PATH, "a") as f:
        f.write(f"[{timestamp}] {msg}\n")

# ------------------------------------------------------------------------------
# Save membership to local file
# ------------------------------------------------------------------------------
def write_local_membership_file():
    """Write MEMBERSHIP to membership_node_{NODE_ID}.json so each node has its own copy."""
    if not LOCAL_MEMBERSHIP_FILE:
        return
    try:
        with open(LOCAL_MEMBERSHIP_FILE, "w") as f:
            json.dump(MEMBERSHIP, f, indent=4)
    except Exception as e:
        log_event(f"Error writing local membership file: {e}")

# ------------------------------------------------------------------------------
# Helper: send_packet
# ------------------------------------------------------------------------------
def send_packet(target, packet):
    """Send a packet to a target node and return its response (if any)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Optionally set timeouts to avoid indefinite blocking
        s.connect((target['host'], target['port']))
        s.sendall(packet)
        response = s.recv(BUFFER_SIZE)
        s.close()
        return response
    except Exception:
        return None

# ------------------------------------------------------------------------------
# Leader heartbeats & election
# ------------------------------------------------------------------------------
def send_heartbeat():
    """Leader periodically sends heartbeat messages to all other nodes."""
    while NODE_ROLE == "LEADER":
        for node in MEMBERSHIP:
            if node['id'] == NODE_ID:
                continue
            try:
                pkt = create_packet(REQ_HRTBT, str(NODE_ID))
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((node['host'], node['port']))
                s.sendall(pkt)
                s.close()
            except Exception:
                pass
        time.sleep(HEARTBEAT_INTERVAL)

def election_listener(conn):
    """Handle incoming election or heartbeat messages."""
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
            # If we have a higher ID, respond OK and start our own election
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
            log_event(f"New leader announced: {LEADER_INFO}")
    except Exception as e:
        log_event(f"[Election Listener] Error: {e}")
    finally:
        conn.close()

def initiate_election():
    """Start an election by sending REQ_ELEC to nodes with higher IDs."""
    global NODE_ROLE, LEADER_INFO
    log_event("Initiating election...")
    responses_received = 0
    for node in MEMBERSHIP:
        if node['id'] > NODE_ID:
            try:
                response = send_packet(node, create_packet(REQ_ELEC, str(NODE_ID)))
                if response:
                    r_cmd, _, r_status = parse_packet(response)
                    if r_cmd == RES_OK_ELEC:
                        responses_received += 1
                        log_event(f"Received election OK from node {node['id']}")
            except Exception:
                pass

    if responses_received == 0:
        NODE_ROLE = "LEADER"
        LEADER_INFO = {"id": NODE_ID, "host": MY_HOST, "port": MY_PORT}
        log_event(f"I am the new leader (node {NODE_ID}).")
        for node in MEMBERSHIP:
            if node['id'] == NODE_ID:
                continue
            try:
                send_packet(node, create_packet(REQ_COORD, str(NODE_ID)))
            except Exception:
                pass
        threading.Thread(target=send_heartbeat, daemon=True).start()
    else:
        # Wait for coordinator
        timeout = HEARTBEAT_TIMEOUT
        waited = 0
        while waited < timeout and LEADER_INFO is None:
            time.sleep(1)
            waited += 1
        if LEADER_INFO is None:
            NODE_ROLE = "LEADER"
            LEADER_INFO = {"id": NODE_ID, "host": MY_HOST, "port": MY_PORT}
            log_event("Timeout waiting for coordinator. Becoming leader anyway.")
            for node in MEMBERSHIP:
                if node['id'] == NODE_ID:
                    continue
                try:
                    send_packet(node, create_packet(REQ_COORD, str(NODE_ID)))
                except Exception:
                    pass
            threading.Thread(target=send_heartbeat, daemon=True).start()

    log_event(f"Election completed. Current leader: {LEADER_INFO}")

def election_monitor():
    """If FOLLOWER, monitor heartbeat. If timed out, initiate election."""
    global LAST_HB
    while True:
        if NODE_ROLE == "FOLLOWER":
            elapsed = time.time() - LAST_HB
            if elapsed > HEARTBEAT_TIMEOUT:
                log_event(f"Heartbeat timeout (elapsed {elapsed:.2f}s). Starting election.")
                initiate_election()
                LAST_HB = time.time()
        time.sleep(1)

# ------------------------------------------------------------------------------
# Pull-based replication for messages & accounts
# ------------------------------------------------------------------------------
def messages_sync_monitor():
    """
    Followers periodically send REQ_PULL to the leader to get the data.
    Also for newly joined nodes, we do a post-startup pull (see post_startup_pull).
    """
    while True:
        time.sleep(10)  # how often to sync
        if NODE_ROLE == "FOLLOWER" and LEADER_INFO is not None:
            do_pull_from_leader()

def do_pull_from_leader():
    """Send REQ_PULL to LEADER_INFO and apply the data if successful."""
    if LEADER_INFO is None:
        return
    try:
        pkt = create_packet(REQ_PULL, "")
        response = send_packet(LEADER_INFO, pkt)
        if response:
            cmd, payload, status = parse_packet(response)
            if cmd == RES_PULL:
                update_local_data(payload)
    except Exception as e:
        log_event(f"Error pulling data from leader: {e}")

def gather_all_data(users):
    """
    On the leader, gather a unified snapshot of:
      - The entire user dictionary
      - All messages in MESSAGES_DIR
    Returns JSON with { "users": {...}, "messages": {...} }
    """
    from responses import MESSAGES_DIR
    data_dict = {"users": users, "messages": {}}

    if os.path.exists(MESSAGES_DIR):
        for fname in os.listdir(MESSAGES_DIR):
            if fname.endswith(".dat"):
                username = fname[:-4]
                path = os.path.join(MESSAGES_DIR, fname)
                with open(path, "r") as f:
                    lines = f.read().splitlines()
                data_dict["messages"][username] = lines

    return json.dumps(data_dict)

def update_local_data(data_json):
    """
    On the follower, parse the incoming JSON, overwrite local user + message data.
    """
    from responses import MESSAGES_DIR, USERS_FILE
    import json

    try:
        data_dict = json.loads(data_json)
    except:
        return

    global global_users
    global_users.clear()
    global_users.update(data_dict.get("users", {}))

    if USERS_FILE:
        try:
            with open(USERS_FILE, "w") as f:
                json.dump(global_users, f)
        except Exception as e:
            log_event(f"Error writing local USERS_FILE: {e}")

    messages = data_dict.get("messages", {})
    if not os.path.exists(MESSAGES_DIR):
        os.makedirs(MESSAGES_DIR, exist_ok=True)
    for username, lines in messages.items():
        user_file = os.path.join(MESSAGES_DIR, f"{username}.dat")
        with open(user_file, "w") as f:
            for line in lines:
                f.write(line + "\n")

# ------------------------------------------------------------------------------
# Pull-based membership
# ------------------------------------------------------------------------------
def do_membership_pull_from_leader():
    """Ask the leader for its current MEMBERSHIP using REQ_MEM/RES_MEM."""
    if LEADER_INFO is None:
        return
    try:
        pkt = create_packet(REQ_MEM, "")
        response = send_packet(LEADER_INFO, pkt)
        if response:
            cmd, payload, status = parse_packet(response)
            if cmd == RES_MEM:
                new_membership = json.loads(payload)
                update_local_membership(new_membership)
    except Exception as e:
        log_event(f"Error pulling membership from leader: {e}")

def update_local_membership(new_membership):
    """Helper to set MEMBERSHIP, write local file, etc."""
    global MEMBERSHIP
    MEMBERSHIP = new_membership
    write_local_membership_file()

# ------------------------------------------------------------------------------
# Membership join & replication
# ------------------------------------------------------------------------------
def handle_join(conn, data, log_path):
    """
    Leader merges new node, updates MEMBERSHIP, writes local file,
    then replicates membership to all currently running nodes.
    """
    global MEMBERSHIP, LEADER_INFO
    if NODE_ROLE == "LEADER":
        try:
            ip, port_str = data.split(":")
            port = int(port_str)
        except Exception:
            send_response(conn, RES_ERR_REQ_FMT, "Invalid join format. Expected ip:port")
            return

        # If already in membership, return existing info
        for node in MEMBERSHIP:
            if node['host'] == ip and node['port'] == port:
                join_info = json.dumps({"id": node["id"], "membership": MEMBERSHIP})
                send_response(conn, RES_JOIN, join_info)
                return

        # Assign a new ID
        new_id = max(n['id'] for n in MEMBERSHIP) + 1 if MEMBERSHIP else 1
        new_node = {"id": new_id, "host": ip, "port": port}
        MEMBERSHIP.append(new_node)

        append_to_log(log_path, REQ_JOIN, f"{ip}:{port}|{new_id}")
        join_info = json.dumps({"id": new_id, "membership": MEMBERSHIP})
        send_response(conn, RES_JOIN, join_info)
        log_event(f"New node joined: {new_node}")

        # Update leader's local membership file
        write_local_membership_file()

        # Replicate membership to all existing nodes
        replicate_membership()
    else:
        # If not leader, forward to leader if known
        if LEADER_INFO:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((LEADER_INFO['host'], LEADER_INFO['port']))
                s.sendall(create_packet(REQ_JOIN, data))
                response = s.recv(BUFFER_SIZE)
                conn.sendall(response)
                s.close()
            except Exception:
                send_response(conn, RES_ERR_SERVER, "Leader unreachable.")
        else:
            send_response(conn, RES_ERR_SERVER, "No leader elected.")

def replicate_membership():
    """
    Leader sends REQ_MUP to all known nodes (that are currently in MEMBERSHIP).
    Each follower updates its local membership file upon receiving REQ_MUP.
    """
    membership_json = json.dumps(MEMBERSHIP)
    for node in MEMBERSHIP:
        if node['id'] == NODE_ID:
            continue
        try:
            send_packet(node, create_packet(REQ_MUP, membership_json))
        except Exception as e:
            log_event(f"Failed to replicate membership to node {node['id']}: {e}")

def handle_membership_update(conn, payload):
    """
    Follower updates its MEMBERSHIP from the leader's broadcast.
    Writes local membership file.
    """
    try:
        new_membership = json.loads(payload)
        update_local_membership(new_membership)
    except Exception as e:
        log_event(f"Error in handle_membership_update: {e}")

# ------------------------------------------------------------------------------
# Handling REQ_MEM: a node asks the leader for membership
# ------------------------------------------------------------------------------
def handle_membership_request(conn):
    """If we are leader, return MEMBERSHIP; else forward or error."""
    if NODE_ROLE == "LEADER":
        membership_json = json.dumps(MEMBERSHIP)
        send_response(conn, RES_MEM, membership_json)
    else:
        if LEADER_INFO:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((LEADER_INFO['host'], LEADER_INFO['port']))
                s.sendall(create_packet(REQ_MEM, ""))  # just forward
                response = s.recv(BUFFER_SIZE)
                conn.sendall(response)
                s.close()
            except Exception:
                send_response(conn, RES_ERR_SERVER, "Leader unreachable.")
        else:
            send_response(conn, RES_ERR_SERVER, "No leader elected.")

# ------------------------------------------------------------------------------
# Client Handler
# ------------------------------------------------------------------------------
def client_handler(conn, client_address, users, log_path):
    conn.settimeout(10)
    try:
        while True:
            try:
                data = conn.recv(BUFFER_SIZE)
            except socket.timeout:
                continue
            if not data:
                break

            try:
                cmd, payload, status = parse_packet(data)
            except Exception:
                continue

            # 1) Check for membership update
            if cmd == REQ_MUP:
                handle_membership_update(conn, payload)
                continue

            # 2) Join request
            if cmd == REQ_JOIN:
                handle_join(conn, payload, log_path)
                continue

            # 3) If it's a request for membership (REQ_MEM)
            if cmd == REQ_MEM:
                handle_membership_request(conn)
                continue

            # 4) Replicated commands
            if cmd in [REQ_REG, REQ_SET, REQ_DEL, REQ_UPA, REQ_DME]:
                if NODE_ROLE == "LEADER":
                    # replicate to other nodes
                    for node in MEMBERSHIP:
                        if node['id'] == NODE_ID:
                            continue
                        try:
                            _ = send_packet(node, create_packet(cmd, payload))
                        except Exception as e:
                            log_event(f"[Replication] Node {node['id']} unreachable: {e}")

                    append_to_log(log_path, cmd, payload)

                    # apply locally
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
                    # Forward to leader
                    if LEADER_INFO:
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.connect((LEADER_INFO['host'], LEADER_INFO['port']))
                            s.sendall(data)
                            response = s.recv(BUFFER_SIZE)
                            conn.sendall(response)
                            s.close()
                        except Exception:
                            send_response(conn, RES_ERR_SERVER, "Leader unreachable.")
                    else:
                        send_response(conn, RES_ERR_SERVER, "No leader elected.")

            # 5) Pull-based replication request
            elif cmd == REQ_PULL:
                if NODE_ROLE == "LEADER":
                    all_data = gather_all_data(users)
                    send_response(conn, RES_PULL, all_data)
                else:
                    if LEADER_INFO:
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.connect((LEADER_INFO['host'], LEADER_INFO['port']))
                            s.sendall(data)
                            response = s.recv(BUFFER_SIZE)
                            conn.sendall(response)
                            s.close()
                        except Exception:
                            send_response(conn, RES_ERR_SERVER, "Leader unreachable.")
                    else:
                        send_response(conn, RES_ERR_SERVER, "No leader elected.")

            # 6) Non-replicated queries
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
        log_event(f"[Client Handler] Error: {e}")
    finally:
        conn.close()

def handle_connection(conn, addr, users, log_path):
    """
    Distinguish election messages vs. normal client membership/replication commands.
    """
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
            client_handler(conn, addr, users, log_path)
    except Exception as e:
        log_event(f"[Connection Handler] Error: {e}")
        conn.close()

# ------------------------------------------------------------------------------
# Startup Logic
# ------------------------------------------------------------------------------
def load_users():
    """
    Load from the node-specific user file (USERS_FILE). 
    If none exist, create a default user. Store in global_users.
    """
    from responses import USERS_FILE
    import json

    if USERS_FILE is None:
        return {}

    if not os.path.exists(USERS_FILE):
        default_username = "kakali121"
        default_pass = "Yunlei1207~"
        temp = {default_username: hash_password_sha256(default_pass)}
        with open(USERS_FILE, "w") as f:
            json.dump(temp, f)
        log_event(f"No user file found. Created default user '{default_username}'.")
        return temp
    else:
        try:
            with open(USERS_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            log_event(f"Error reading user file: {e}, resetting to default user.")
            default_username = "kakali121"
            default_pass = "Yunlei1207~"
            temp = {default_username: hash_password_sha256(default_pass)}
            with open(USERS_FILE, "w") as f:
                json.dump(temp, f)
            return temp

def load_local_membership_or_fallback(initial_membership_path):
    """
    If 'common/membership_node_{NODE_ID}.json' exists, load from it.
    Otherwise, load from the path provided by --membership,
    and then write out to 'membership_node_{NODE_ID}.json' for local usage.
    """
    global LOCAL_MEMBERSHIP_FILE
    local_path = f"common/membership_node_{NODE_ID}.json"
    LOCAL_MEMBERSHIP_FILE = local_path

    if os.path.exists(local_path):
        # We already have a local membership file, load it
        try:
            with open(local_path, "r") as f:
                membership_data = json.load(f)
            return membership_data
        except Exception as e:
            log_event(f"Error reading local membership file: {e}")
            # fallback
    # else load from the initial membership path
    try:
        with open(initial_membership_path, "r") as f:
            membership_data = json.load(f)
    except Exception as e:
        print(f"Error loading membership file {initial_membership_path}: {e}")
        sys.exit(1)

    # write membership_data to local_path
    try:
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        with open(local_path, "w") as f:
            json.dump(membership_data, f, indent=4)
    except Exception as e:
        log_event(f"Error writing local membership file: {e}")
    return membership_data

def post_startup_pull():
    """
    For a node that has just started: if it ends up as a FOLLOWER with a known leader,
    do an immediate membership pull (REQ_MEM) + message pull (REQ_PULL).
    This ensures newly joined nodes get fully updated membership & data.
    """
    time.sleep(3)
    if NODE_ROLE == "FOLLOWER" and LEADER_INFO is not None:
        log_event("Doing post-startup membership & data pull from leader.")
        do_membership_pull_from_leader()   # get latest membership
        do_pull_from_leader()              # get user/messages

def node_server():
    global global_users
    global_users = load_users()

    log_path = f"common/logs/node_{NODE_ID}.log"

    # Replay any existing replication log
    entries = replay_log(log_path)
    for entry in entries:
        cmd, payload = entry["cmd"], entry["payload"]
        if cmd == b"REGISTER":
            username, password = payload.split("|")
            handle_reg(None, global_users, username, password)
        elif cmd == b"SETPFILE":
            username, message, target = payload.split("|")
            handle_set(None, global_users, username, message, target)
        elif cmd == b"DELEUSER":
            handle_delete(None, global_users, payload)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((MY_HOST, MY_PORT))
    server_socket.listen(25)

    log_event(f"Node {NODE_ID} listening on {MY_HOST}:{MY_PORT} as {NODE_ROLE}")

    # Start a thread that accepts connections
    def accept_loop():
        while True:
            try:
                conn, addr = server_socket.accept()
                threading.Thread(
                    target=handle_connection,
                    args=(conn, addr, global_users, log_path),
                    daemon=True
                ).start()
            except Exception as e:
                log_event(f"[Server] Error accepting connection: {e}")

    threading.Thread(target=accept_loop, daemon=True).start()

    # Also do a post-startup pull to sync data & membership if we remain a follower
    threading.Thread(target=post_startup_pull, daemon=True).start()

    # The main thread can sleep forever
    while True:
        time.sleep(10)

# ------------------------------------------------------------------------------
# Main Entry
# ------------------------------------------------------------------------------
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

    # Set up per-node directories (messages, user file) via responses.py
    set_node_id(NODE_ID)

    # Also set up an events log
    os.makedirs("common/logs", exist_ok=True)
    EVENTS_LOG_PATH = f"common/logs/node_{NODE_ID}_events.log"

    # Load membership from 'membership_node_{NODE_ID}.json' or fallback
    MEMBERSHIP = load_local_membership_or_fallback(args.membership)

    # Start as FOLLOWER
    NODE_ROLE = "FOLLOWER"
    LEADER_INFO = None
    log_event(f"Node {NODE_ID} starting as FOLLOWER. No leader initially.")

    # Start an election monitor (listens for heartbeats)
    threading.Thread(target=election_monitor, daemon=True).start()

    # We do NOT call initiate_election here; we wait to see if there's an existing leader.
    # The node remains follower, unless no heartbeats appear within HEARTBEAT_TIMEOUT.

    # Start pull-based replication monitor for messages
    threading.Thread(target=messages_sync_monitor, daemon=True).start()

    # Finally, run the server
    node_server()
