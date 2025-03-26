import socket
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.protocol import *

def send_join_request(replica_hostport):
    leader_host = "127.0.0.1"
    leader_port = 9999

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((leader_host, leader_port))
        packet = create_packet(REQ_JOI, replica_hostport)
        s.sendall(packet)
        response = s.recv(BUFFER_SIZE)
        cmd, payload, status = parse_packet(response)
        print(f"📩 Response from Leader: {cmd.decode()} | {payload} | {status}")

    except Exception as e:
        print(f"❌ Failed to join: {e}")
    finally:
        s.close()

if __name__ == "__main__":
    # IP and port of the new follower
    send_join_request("127.0.0.1:9994")