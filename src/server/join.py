#!/usr/bin/env python3
"""
join.py - Script to join a node to the cluster.

Usage:
    python3 join.py --leader_host <leader_ip> --leader_port <leader_port> --new_host <new_node_ip> --new_port <new_node_port>
"""

import socket
import argparse
import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.protocol import *

def send_join_request(leader_host, leader_port, new_host, new_port):
    join_payload = f"{new_host}:{new_port}"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((leader_host, leader_port))
        packet = create_packet(REQ_JOIN, join_payload)
        s.sendall(packet)
        response = s.recv(BUFFER_SIZE)
        cmd, payload, status = parse_packet(response)
        if cmd == RES_JOIN:
            join_info = json.loads(payload)
            print("✅ Joined successfully!")
            print("Assigned ID:", join_info["id"])
            print("Updated Membership:")
            print(json.dumps(join_info["membership"], indent=4))
        else:
            print("❌ Join failed:", payload)
    except Exception as e:
        print("❌ Failed to join:", e)
    finally:
        s.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--leader_host", required=True, help="Leader IP address")
    parser.add_argument("--leader_port", type=int, required=True, help="Leader port")
    parser.add_argument("--new_host", required=True, help="New node's IP address")
    parser.add_argument("--new_port", type=int, required=True, help="New node's port")
    args = parser.parse_args()

    send_join_request(args.leader_host, args.leader_port, args.new_host, args.new_port)
