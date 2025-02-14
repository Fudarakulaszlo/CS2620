"""
* File: server_tests.py
* Author: Áron Vékássy, Karen Li
*
* This file contains unit tests for the server code.
* It simulates stopping the server by raising KeyboardInterrupt,
* as would be used in production to stop the program.
"""

import unittest
from unittest.mock import patch, MagicMock, mock_open, call
import os
import sys
import json
import threading
import time

# Adjust the module search path so that the server module is found.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import server.server as server

# ---------------------------------------------------------------------------
# Dummy Socket for testing handle_client and server socket
# ---------------------------------------------------------------------------
class DummySocket:
    def __init__(self, responses=None):
        """If responses is provided, it will be used for successive recv() calls."""
        self.responses = responses if responses is not None else []
        self.recv_counter = 0
        self.sent_data = []
        self.closed = False

    def recv(self, bufsize):
        if self.recv_counter < len(self.responses):
            resp = self.responses[self.recv_counter]
            self.recv_counter += 1
            return resp
        else:
            return b""

    def sendall(self, data):
        self.sent_data.append(data)

    def close(self):
        self.closed = True

# ---------------------------------------------------------------------------
# Tests for argument parsing
# ---------------------------------------------------------------------------
class TestParseArgs(unittest.TestCase):
    @patch('argparse._sys.argv', ['server.py', '-p', '1234'])
    def test_parse_args_port(self):
        args = server.parse_args()
        self.assertEqual(args.port, 1234)
        self.assertFalse(args.usage)

    @patch('argparse._sys.argv', ['server.py', '-h'])
    def test_parse_args_usage(self):
        args = server.parse_args()
        self.assertTrue(args.usage)

# ---------------------------------------------------------------------------
# Tests for loading users
# ---------------------------------------------------------------------------
class TestLoadUsers(unittest.TestCase):
    @patch('server.server.os.path.exists', return_value=False)
    @patch("builtins.open", new_callable=mock_open)
    def test_load_users_no_file(self, mock_file, mock_exists):
        users = server.load_users()
        # Default user "kakali121" should be created when no file exists.
        self.assertIn("kakali121", users)
        # Ensure that USERS_FILE was opened for writing at some point.
        mock_file.assert_any_call(server.USERS_FILE, "w")

    @patch('server.server.os.path.exists', return_value=True)
    @patch("builtins.open", new_callable=mock_open, read_data='{"Alice": "hashed_pw"}')
    def test_load_users_existing(self, mock_file, mock_exists):
        users = server.load_users()
        self.assertIn("Alice", users)

    @patch('server.server.os.path.exists', return_value=True)
    @patch("builtins.open", new_callable=mock_open, read_data='invalid json')
    def test_load_users_decode_error(self, mock_file, mock_exists):
        # If JSON decoding fails, load_users resets the file and creates a default user.
        users = server.load_users()
        self.assertIn("kakali121", users)

# ---------------------------------------------------------------------------
# Tests for handling a client connection
# ---------------------------------------------------------------------------
class TestHandleClient(unittest.TestCase):
    def test_handle_client_unknown_command(self):
        # Simulate a single request then a disconnect.
        responses_list = [b"dummy_request", b""]  # Second recv returns empty (disconnect)
        dummy_sock = DummySocket(responses_list)
        client_address = ("127.0.0.1", 5000)
        users = {"Alice": "hashed_pw"}
        # Patch parse_json to return ("CHECK___", "Alice", RES_OK)
        with patch('server.server.parse_json', return_value=("CHECK___", "Alice", server.RES_OK)):
            # Patch send_response in the server.responses module.
            with patch('server.responses.send_response') as mock_send_response:
                server.handle_client(dummy_sock, client_address, users)
                # Verify that send_response was called (for the CHECK command)
                self.assertTrue(mock_send_response.called)
        # After handling, the socket should be closed.
        self.assertTrue(dummy_sock.closed)

# ---------------------------------------------------------------------------
# Tests for starting the server
# ---------------------------------------------------------------------------
class TestStartServer(unittest.TestCase):
    @patch('server.server.socket.socket')
    @patch('server.server.load_users', return_value={"Alice": "hashed_pw"})
    def test_start_server_keyboard_interrupt(self, mock_load_users, mock_socket_class):
        # Immediately raise KeyboardInterrupt on accept to simulate a shutdown.
        dummy_server_socket = MagicMock()
        dummy_server_socket.accept.side_effect = KeyboardInterrupt
        mock_socket_class.return_value = dummy_server_socket
        args = MagicMock()
        args.port = 1234
        server.start_server(args)
        # Verify that the server socket is closed.
        dummy_server_socket.close.assert_called()

    @patch('server.server.socket.socket')
    @patch('server.server.load_users', return_value={"Alice": "hashed_pw"})
    def test_start_server_accept_once(self, mock_load_users, mock_socket_class):
        # Accept one dummy client connection then raise KeyboardInterrupt.
        dummy_server_socket = MagicMock()
        dummy_client_socket = MagicMock()
        dummy_server_socket.accept.side_effect = [
            (dummy_client_socket, ("127.0.0.1", 1234)),
            KeyboardInterrupt()
        ]
        mock_socket_class.return_value = dummy_server_socket
        args = MagicMock()
        args.port = 1234

        # Patch handle_client so that it returns immediately.
        with patch('server.server.handle_client') as mock_handle_client:
            server.start_server(args)
            mock_handle_client.assert_called_once_with(dummy_client_socket, ("127.0.0.1", 1234), {"Alice": "hashed_pw"})
        # Ensure the server socket is closed.
        dummy_server_socket.close.assert_called()

    def test_start_server_in_thread(self):
        # Run start_server in a separate thread to avoid blocking.
        with patch('server.server.socket.socket') as mock_socket_class, \
             patch('server.server.load_users', return_value={"Alice": "hashed_pw"}):
            dummy_server_socket = MagicMock()
            # Simulate one accept then a KeyboardInterrupt.
            dummy_client_socket = MagicMock()
            dummy_server_socket.accept.side_effect = [
                (dummy_client_socket, ("127.0.0.1", 1234)),
                KeyboardInterrupt()
            ]
            mock_socket_class.return_value = dummy_server_socket
            args = MagicMock()
            args.port = 1234

            # Patch handle_client so that it returns immediately.
            with patch('server.server.handle_client') as mock_handle_client:
                server_thread = threading.Thread(target=server.start_server, args=(args,))
                server_thread.daemon = True
                server_thread.start()
                # Wait briefly for the thread to finish.
                server_thread.join(timeout=2)
                self.assertFalse(server_thread.is_alive(), "Server thread should have terminated.")
                mock_handle_client.assert_called_once_with(dummy_client_socket, ("127.0.0.1", 1234), {"Alice": "hashed_pw"})
            # Ensure the server socket is closed.
            dummy_server_socket.close.assert_called()

# ---------------------------------------------------------------------------
# Tests for main()
# ---------------------------------------------------------------------------
class TestMain(unittest.TestCase):
    @patch('server.server.start_server')
    @patch('server.server.parse_args', return_value=MagicMock(port=1234, usage=False))
    def test_main_normal(self, mock_parse_args, mock_start_server):
        with patch('sys.exit') as mock_exit:
            server.main()
            mock_start_server.assert_called()
            mock_exit.assert_not_called()

    @patch('server.server.parse_args', return_value=MagicMock(port=0, usage=False))
    def test_main_no_port(self, mock_parse_args):
        with self.assertRaises(SystemExit):
            server.main()

    @patch('server.server.parse_args', return_value=MagicMock(port=1234, usage=True))
    def test_main_usage(self, mock_parse_args):
        with patch('sys.exit') as mock_exit:
            server.main()
            mock_exit.assert_called_with(0)

# ---------------------------------------------------------------------------
# Run all tests
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    unittest.main()
