"""
* File: request_tests.py
* Author: Áron Vékássy, Karen Li
*
* This file contains the unit tests for the client request code.
"""

import unittest
from unittest.mock import MagicMock, patch
import time
import sys
import os

# Import the module under test.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import client.requests as requests

# A simple fake socket to simulate sendall() and recv() behavior.
class FakeSocket:
    def __init__(self, response):
        self.response = response
        self.sent_data = None

    def sendall(self, data):
        self.sent_data = data

    def recv(self, bufsize):
        # Return the pre-defined response regardless of bufsize.
        return self.response

class TestRequests(unittest.TestCase):

    @patch('client.requests.create_json')
    @patch('client.requests.parse_json')
    def test_send_request_json(self, mock_parse_json, mock_create_json):
        test_command = "CMD"
        test_payload = "payload"

        # Set up our fake response and socket.
        fake_response_str = "server_response"
        # Since send_request expects to decode the response, simulate a bytes response.
        fake_response_bytes = fake_response_str.encode()

        # Set the return values for our patched functions.
        mock_create_json.return_value = "json_request"
        mock_parse_json.return_value = ("cmd_result", "payload_result", "status_result")

        # Patch global variables used in send_request.
        with patch('client.requests.USE_JSON', True), \
             patch('client.requests.CHE_TIME', False), \
             patch('client.requests.BUFFER_SIZE', 1024):
            fake_socket = FakeSocket(fake_response_bytes)

            # Also test the behavior when the command is passed as bytes.
            result = requests.send_request(fake_socket, test_command.encode(), test_payload)

            # Verify that command was decoded (i.e. not passed in as bytes to create_json).
            mock_create_json.assert_called_once_with("CMD", test_payload)
            # Check that sendall was called with the encoded JSON string.
            self.assertEqual(fake_socket.sent_data, "json_request".encode())
            # Ensure that parse_json was called with the decoded response.
            mock_parse_json.assert_called_once_with(fake_response_str)
            # Check that the result is what parse_json returned.
            self.assertEqual(result, ("cmd_result", "payload_result", "status_result"))

    @patch('client.requests.create_packet')
    @patch('client.requests.parse_packet')
    def test_send_request_packet(self, mock_parse_packet, mock_create_packet):
        test_command = "CMD"
        test_payload = "payload"

        # For packet mode, our fake response will be in bytes.
        fake_response_bytes = b"packet_response"

        mock_create_packet.return_value = b"packet_data"
        mock_parse_packet.return_value = ("cmd_pkt", "payload_pkt", "status_pkt")

        with patch('client.requests.USE_JSON', False), \
             patch('client.requests.CHE_TIME', False), \
             patch('client.requests.BUFFER_SIZE', 1024):
            fake_socket = FakeSocket(fake_response_bytes)
            result = requests.send_request(fake_socket, test_command, test_payload)

            mock_create_packet.assert_called_once_with(test_command, test_payload)
            self.assertEqual(fake_socket.sent_data, b"packet_data")
            mock_parse_packet.assert_called_once_with(fake_response_bytes)
            self.assertEqual(result, ("cmd_pkt", "payload_pkt", "status_pkt"))

    # Test the wrapper function for checking if a user exists.
    @patch('client.requests.send_request')
    def test_request_check_user_exists(self, mock_send_request):
        fake_socket = MagicMock()
        username = "Alice"
        mock_send_request.return_value = ("cmd_exist", "payload_exist", "status_exist")

        result = requests.request_check_user_exists(fake_socket, username)
        mock_send_request.assert_called_once_with(fake_socket, requests.REQ_CHE, username)
        self.assertEqual(result, ("cmd_exist", "payload_exist", "status_exist"))

    # Test the registration request.
    @patch('client.requests.hash_password_sha256')
    @patch('client.requests.send_request')
    def test_request_register(self, mock_send_request, mock_hash):
        fake_socket = MagicMock()
        username = "Bob"
        password = "secret"
        dummy_hash = "hashed_secret"
        mock_hash.return_value = dummy_hash
        mock_send_request.return_value = ("cmd_reg", "payload_reg", "status_reg")

        result = requests.request_register(fake_socket, username, password)
        expected_payload = f"{username}|{dummy_hash}"
        mock_send_request.assert_called_once_with(fake_socket, requests.REQ_REG, expected_payload)
        self.assertEqual(result, ("cmd_reg", "payload_reg", "status_reg"))

    # Test the login request.
    @patch('client.requests.hash_password_sha256')
    @patch('client.requests.send_request')
    def test_request_login(self, mock_send_request, mock_hash):
        fake_socket = MagicMock()
        username = "Charlie"
        password = "mypassword"
        dummy_hash = "hashed_mypassword"
        mock_hash.return_value = dummy_hash
        mock_send_request.return_value = ("cmd_log", "payload_log", "status_log")

        result = requests.request_login(fake_socket, username, password)
        expected_payload = f"{username}|{dummy_hash}"
        mock_send_request.assert_called_once_with(fake_socket, requests.REQ_LOG, expected_payload)
        self.assertEqual(result, ("cmd_log", "payload_log", "status_log"))

    # Test setting a profile (e.g. sending a message).
    @patch('client.requests.send_request')
    def test_request_set_profile(self, mock_send_request):
        fake_socket = MagicMock()
        username = "Dave"
        message = "Hello!"
        target_user = "Eve"
        mock_send_request.return_value = ("cmd_set", "payload_set", "status_set")

        result = requests.request_set_profile(fake_socket, username, message, target_user)
        expected_payload = f"{username}|{message}|{target_user}"
        mock_send_request.assert_called_once_with(fake_socket, requests.REQ_SET, expected_payload)
        self.assertEqual(result, ("cmd_set", "payload_set", "status_set"))

    # Test updating a profile.
    @patch('client.requests.send_request')
    def test_request_update_profile(self, mock_send_request):
        fake_socket = MagicMock()
        username = "Frank"
        mock_send_request.return_value = ("cmd_upa", "payload_upa", "status_upa")

        result = requests.request_update_profile(fake_socket, username)
        mock_send_request.assert_called_once_with(fake_socket, requests.REQ_UPA, username)
        self.assertEqual(result, ("cmd_upa", "payload_upa", "status_upa"))

    # Test getting a profile.
    @patch('client.requests.send_request')
    def test_request_get_profile(self, mock_send_request):
        fake_socket = MagicMock()
        username = "Grace"
        mock_send_request.return_value = ("cmd_get", "payload_get", "status_get")

        result = requests.request_get_profile(fake_socket, username)
        mock_send_request.assert_called_once_with(fake_socket, requests.REQ_GET, username)
        self.assertEqual(result, ("cmd_get", "payload_get", "status_get"))

    # Test deleting a message.
    @patch('client.requests.send_request')
    def test_request_delete_messages(self, mock_send_request):
        fake_socket = MagicMock()
        username = "Heidi"
        message_id = "msg123"
        mock_send_request.return_value = ("cmd_dme", "payload_dme", "status_dme")

        result = requests.request_delete_messages(fake_socket, username, message_id)
        expected_payload = f"{username}|{message_id}"
        mock_send_request.assert_called_once_with(fake_socket, requests.REQ_DME, expected_payload)
        self.assertEqual(result, ("cmd_dme", "payload_dme", "status_dme"))

    # Test listing users.
    @patch('client.requests.send_request')
    def test_request_list_users(self, mock_send_request):
        fake_socket = MagicMock()
        username = "Ivan"
        mock_send_request.return_value = ("cmd_all", "payload_all", "status_all")

        result = requests.request_list_users(fake_socket, username)
        mock_send_request.assert_called_once_with(fake_socket, requests.REQ_ALL, username)
        self.assertEqual(result, ("cmd_all", "payload_all", "status_all"))

    # Test saving users.
    @patch('client.requests.send_request')
    def test_request_save_users(self, mock_send_request):
        fake_socket = MagicMock()
        username = "Judy"
        mock_send_request.return_value = ("cmd_sav", "payload_sav", "status_sav")

        result = requests.request_save_users(fake_socket, username)
        mock_send_request.assert_called_once_with(fake_socket, requests.REQ_SAV, username)
        self.assertEqual(result, ("cmd_sav", "payload_sav", "status_sav"))

    # Test deleting a profile.
    @patch('client.requests.send_request')
    def test_request_delete_profile(self, mock_send_request):
        fake_socket = MagicMock()
        username = "Kevin"
        mock_send_request.return_value = ("cmd_del", "payload_del", "status_del")

        result = requests.request_delete_profile(fake_socket, username)
        mock_send_request.assert_called_once_with(fake_socket, requests.REQ_DEL, username)
        self.assertEqual(result, ("cmd_del", "payload_del", "status_del"))

    # Test logout.
    @patch('client.requests.send_request')
    def test_request_logout(self, mock_send_request):
        fake_socket = MagicMock()
        username = "Laura"
        mock_send_request.return_value = ("cmd_bye", "payload_bye", "status_bye")

        result = requests.request_logout(fake_socket, username)
        mock_send_request.assert_called_once_with(fake_socket, requests.REQ_BYE, username)
        self.assertEqual(result, ("cmd_bye", "payload_bye", "status_bye"))

if __name__ == '__main__':
    unittest.main()
