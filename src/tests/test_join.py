import unittest
from unittest.mock import patch, MagicMock
import json
import socket
import sys
import os

# Adjust sys.path so we can import from our project root.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from common.protocol import create_packet, parse_packet, REQ_JOIN, RES_JOIN, BUFFER_SIZE
from server.join import send_join_request

# DummySocket to simulate socket behavior
class DummySocket:
    def __init__(self, fake_response):
        self.fake_response = fake_response
        self.sent_data = b""
        self.addr = None
        self.closed = False
    def connect(self, addr):
        self.addr = addr
    def sendall(self, data):
        self.sent_data += data
    def recv(self, bufsize):
        return self.fake_response
    def close(self):
        self.closed = True
    def settimeout(self, t):
        pass

class TestJoin(unittest.TestCase):
    @patch('socket.socket')
    def test_join_success(self, mock_socket_class):
        # Prepare a fake join response from the leader.
        # The leader should return a packet with command RES_JOIN and payload as JSON.
        join_info = {
            "id": 3,
            "membership": [
                {"id": 1, "host": "127.0.0.1", "port": 9001},
                {"id": 2, "host": "127.0.0.1", "port": 9002},
                {"id": 3, "host": "127.0.0.1", "port": 9003}
            ]
        }
        payload = json.dumps(join_info)
        fake_response = create_packet(RES_JOIN, payload)
        dummy_sock = DummySocket(fake_response)
        
        # Configure the mock socket instance to use our dummy socket methods.
        mock_sock_instance = MagicMock()
        mock_sock_instance.connect = dummy_sock.connect
        mock_sock_instance.sendall = dummy_sock.sendall
        mock_sock_instance.recv = dummy_sock.recv
        mock_sock_instance.close = dummy_sock.close
        mock_sock_instance.settimeout = dummy_sock.settimeout
        
        # When socket.socket() is called, return our dummy socket.
        mock_socket_class.return_value = mock_sock_instance

        # Capture printed output.
        from io import StringIO
        old_stdout = sys.stdout
        sys.stdout = StringIO()

        send_join_request("127.0.0.1", 9001, "127.0.0.1", 9003)
        output = sys.stdout.getvalue()
        sys.stdout = old_stdout

        # Verify expected output.
        self.assertIn("✅ Joined successfully!", output)
        self.assertIn("Assigned ID:", output)
        self.assertIn("Updated Membership:", output)
        # Verify that connect was called with the correct leader address.
        mock_sock_instance.connect.assert_called_with(("127.0.0.1", 9001))

    @patch('socket.socket')
    def test_join_failure(self, mock_socket_class):
        # Simulate a connection failure by having connect() raise an Exception.
        mock_sock_instance = MagicMock()
        mock_sock_instance.connect.side_effect = Exception("Connection error")
        mock_socket_class.return_value = mock_sock_instance

        from io import StringIO
        old_stdout = sys.stdout
        sys.stdout = StringIO()

        send_join_request("127.0.0.1", 9001, "127.0.0.1", 9003)
        output = sys.stdout.getvalue()
        sys.stdout = old_stdout

        self.assertIn("❌ Failed to join:", output)

if __name__ == '__main__':
    unittest.main()
