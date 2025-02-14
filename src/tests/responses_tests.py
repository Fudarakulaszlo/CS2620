"""
* File: response_tests.py
* Author: Áron Vékássy, Karen Li
*
* This file contains unit tests for the response handling code.
"""

import unittest
from unittest.mock import patch, MagicMock, mock_open
import os
import json
import sys

# Adjust the path so that the parent directory is included.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import server.responses as responses  # Import the module under test

# A dummy socket to capture data sent by send_response and other functions.
class DummySocket:
    def __init__(self):
        self.sent_data = None
        self.closed = False
    def sendall(self, data):
        self.sent_data = data
    def close(self):
        self.closed = True

class TestResponse(unittest.TestCase):

    def setUp(self):
        # Ensure that we are using JSON mode for these tests.
        responses.USE_JSON = True

    @patch('server.responses.create_json', return_value="dummy_response")
    def test_send_response_json(self, mock_create_json):
        dummy_sock = DummySocket()
        # Test with status as string (and payload provided).
        responses.send_response(dummy_sock, "TEST_STATUS", "payload")
        mock_create_json.assert_called_once_with("TEST_STATUS", "payload")
        self.assertEqual(dummy_sock.sent_data, "dummy_response".encode())

    @patch('server.responses.create_packet', return_value=b"dummy_packet")
    def test_send_response_packet(self, mock_create_packet):
        dummy_sock = DummySocket()
        responses.USE_JSON = False  # Force packet mode.
        responses.send_response(dummy_sock, "TEST_STATUS", "payload")
        mock_create_packet.assert_called_once_with("TEST_STATUS", "payload")
        self.assertEqual(dummy_sock.sent_data, b"dummy_packet")
        # Reset USE_JSON back to JSON mode.
        responses.USE_JSON = True

    @patch('server.responses.create_json', return_value="dummy_response")
    def test_handle_check_user_exists_found(self, mock_create_json):
        dummy_sock = DummySocket()
        users = {"Alice": "hashed_pw"}
        result = responses.handle_check_user_exists(dummy_sock, users, "Alice")
        self.assertTrue(result)
        mock_create_json.assert_called_once_with(responses.RES_OK.decode(), "✅ Username exists.")
        self.assertEqual(dummy_sock.sent_data, "dummy_response".encode())

    @patch('server.responses.create_json', return_value="dummy_response")
    def test_handle_check_user_exists_not_found(self, mock_create_json):
        dummy_sock = DummySocket()
        users = {"Alice": "hashed_pw"}
        result = responses.handle_check_user_exists(dummy_sock, users, "Bob")
        self.assertFalse(result)
        mock_create_json.assert_called_once_with(responses.RES_ERR_NO_USER, "❌ Username not found.")
        self.assertEqual(dummy_sock.sent_data, "dummy_response".encode())

    @patch('server.responses.create_json', return_value="dummy_response")
    def test_handle_reg_existing_user(self, mock_create_json):
        dummy_sock = DummySocket()
        users = {"Alice": "hashed_pw"}
        result = responses.handle_reg(dummy_sock, users, "Alice", "password")
        self.assertFalse(result)
        mock_create_json.assert_called_once_with(responses.RES_ERR_USER_EXISTS, "❌ Username already exists.")
        self.assertEqual(dummy_sock.sent_data, "dummy_response".encode())

    @patch('server.responses.create_json', return_value="dummy_response")
    @patch("builtins.open", new_callable=mock_open)
    def test_handle_reg_new_user(self, mock_file, mock_create_json):
        dummy_sock = DummySocket()
        users = {}
        result = responses.handle_reg(dummy_sock, users, "Bob", "password")
        self.assertTrue(result)
        self.assertIn("Bob", users)
        # Verify that a file for Bob was opened for writing.
        mock_file.assert_called_with(os.path.join(responses.MESSAGES_DIR, "Bob.dat"), "w")
        mock_create_json.assert_called_once_with(responses.RES_OK.decode(), "✅ Registration successful.")
        self.assertEqual(dummy_sock.sent_data, "dummy_response".encode())

    @patch('server.responses.create_json', return_value="dummy_response")
    def test_handle_log_success(self, mock_create_json):
        dummy_sock = DummySocket()
        password = "secret"
        hashed = responses.hash_password_sha256(password)
        users = {"Alice": hashed}
        result = responses.handle_log(dummy_sock, users, "Alice", "secret")
        self.assertTrue(result)
        mock_create_json.assert_called_once_with(responses.RES_OK.decode(), "✅ Login successful.")
        self.assertEqual(dummy_sock.sent_data, "dummy_response".encode())

    @patch('server.responses.create_json', return_value="dummy_response")
    def test_handle_log_failure(self, mock_create_json):
        dummy_sock = DummySocket()
        users = {"Alice": responses.hash_password_sha256("secret")}
        result = responses.handle_log(dummy_sock, users, "Alice", "wrong")
        self.assertFalse(result)
        mock_create_json.assert_called_once_with(responses.RES_ERR_LOGIN, "❌ Invalid credentials.")
        self.assertEqual(dummy_sock.sent_data, "dummy_response".encode())

    @patch('server.responses.create_json', return_value="dummy_response")
    @patch("builtins.open", new_callable=mock_open)
    def test_handle_set_success(self, mock_file, mock_create_json):
        dummy_sock = DummySocket()
        users = {"Alice": "hashed_pw", "Bob": "hashed_pw"}
        responses.handle_set(dummy_sock, users, "Alice", "Hello", "Bob")
        calls = [
            unittest.mock.call(os.path.join(responses.MESSAGES_DIR, "Alice.dat"), "a"),
            unittest.mock.call(os.path.join(responses.MESSAGES_DIR, "Bob.dat"), "a")
        ]
        mock_file.assert_has_calls(calls, any_order=True)
        mock_create_json.assert_called_once_with(responses.RES_OK.decode(), "✅ Message updated successfully.")
        self.assertEqual(dummy_sock.sent_data, "dummy_response".encode())

    @patch('server.responses.create_json', return_value="dummy_response")
    @patch("builtins.open", new_callable=mock_open, read_data="UNREAD, Hello, Bob\nREAD, Hi, Carol\n")
    def test_handle_update_success(self, mock_file, mock_create_json):
        dummy_sock = DummySocket()
        users = {"Alice": "hashed_pw"}
        responses.handle_update(dummy_sock, users, "Alice")
        # Ensure that the file was opened for reading and then for writing.
        self.assertTrue(mock_file.call_count >= 2)
        mock_create_json.assert_called_once_with(responses.RES_OK.decode(), "✅ User data updated successfully.")
        self.assertEqual(dummy_sock.sent_data, "dummy_response".encode())

    @patch('server.responses.create_json', return_value="dummy_response")
    @patch("builtins.open", new_callable=mock_open, read_data="Message1\nMessage2")
    def test_handle_get_success(self, mock_file, mock_create_json):
        dummy_sock = DummySocket()
        users = {"Alice": "hashed_pw"}
        responses.handle_get(dummy_sock, users, "Alice")
        mock_file.assert_called_with(os.path.join(responses.MESSAGES_DIR, "Alice.dat"), "r")
        mock_create_json.assert_called_once_with(responses.RES_OK.decode(), "Message1\nMessage2")
        self.assertEqual(dummy_sock.sent_data, "dummy_response".encode())

    @patch('server.responses.create_json', return_value="dummy_response")
    @patch("builtins.open", new_callable=mock_open, read_data="Line1\nLine2\nLine3")
    def test_handle_delemsg_success(self, mock_file, mock_create_json):
        dummy_sock = DummySocket()
        users = {"Alice": "hashed_pw"}
        responses.handle_delemsg(dummy_sock, users, "Alice", "1")
        self.assertTrue(mock_file.call_count >= 2)
        mock_create_json.assert_called_once_with(responses.RES_OK.decode(), "✅ Message deleted successfully.")
        self.assertEqual(dummy_sock.sent_data, "dummy_response".encode())

    @patch('server.responses.create_json', return_value="dummy_response")
    def test_handle_delemsg_failure(self, mock_create_json):
        dummy_sock = DummySocket()
        users = {"Alice": "hashed_pw"}
        with patch("builtins.open", side_effect=ValueError):
            responses.handle_delemsg(dummy_sock, users, "Alice", "0")
        mock_create_json.assert_called_once_with(responses.RES_ERR_NO_DATA, "❌ Message not found.")
        self.assertEqual(dummy_sock.sent_data, "dummy_response".encode())

    @patch('server.responses.create_json', return_value="dummy_response")
    def test_handle_all_success(self, mock_create_json):
        dummy_sock = DummySocket()
        users = {"Alice": "hashed_pw", "Bob": "hashed_pw"}
        responses.handle_all(dummy_sock, users, "Alice")
        expected_list = "Alice\nBob"
        mock_create_json.assert_called_once_with(responses.RES_OK.decode(), expected_list)
        self.assertEqual(dummy_sock.sent_data, "dummy_response".encode())

    @patch('server.responses.create_json', return_value="dummy_response")
    @patch("builtins.open", new_callable=mock_open)
    def test_handle_sav(self, mock_file, mock_create_json):
        dummy_sock = DummySocket()
        users = {"Alice": "hashed_pw", "Bob": "hashed_pw"}
        responses.handle_sav(dummy_sock, users)
        mock_file.assert_called_with(responses.USERS_FILE, "w")
        mock_create_json.assert_called_once_with(responses.RES_OK.decode(), "✅ User data saved successfully.")
        self.assertEqual(dummy_sock.sent_data, "dummy_response".encode())

    @patch('server.responses.create_json', return_value="dummy_response")
    @patch("os.remove")
    @patch("builtins.open", new_callable=mock_open)
    def test_handle_delete_success(self, mock_file, mock_os_remove, mock_create_json):
        dummy_sock = DummySocket()
        users = {"Alice": "hashed_pw", "Bob": "hashed_pw"}
        dummy_path = os.path.join(responses.MESSAGES_DIR, "Alice.dat")
        with patch("os.path.exists", return_value=True):
            responses.handle_delete(dummy_sock, users, "Alice")
        self.assertNotIn("Alice", users)
        mock_os_remove.assert_called_with(dummy_path)
        mock_create_json.assert_called_once_with(responses.RES_OK.decode(), "✅ User deleted successfully.")
        self.assertEqual(dummy_sock.sent_data, "dummy_response".encode())

    @patch('server.responses.create_json', return_value="dummy_response")
    def test_handle_delete_failure(self, mock_create_json):
        dummy_sock = DummySocket()
        users = {"Alice": "hashed_pw"}
        responses.handle_delete(dummy_sock, users, "Bob")
        mock_create_json.assert_called_once_with(responses.RES_ERR_LOGIN, "❌ Authentication failed.")
        self.assertEqual(dummy_sock.sent_data, "dummy_response".encode())

    @patch('server.responses.create_json', return_value="dummy_response")
    def test_handle_bye(self, mock_create_json):
        dummy_sock = DummySocket()
        responses.handle_bye(dummy_sock, "Alice")
        mock_create_json.assert_called_once_with(responses.RES_OK.decode(), "👋 Alice You have logged out.")
        self.assertEqual(dummy_sock.sent_data, "dummy_response".encode())
        self.assertTrue(dummy_sock.closed)

if __name__ == '__main__':
    unittest.main()
