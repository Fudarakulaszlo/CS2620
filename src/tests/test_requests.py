import unittest
import sys
import os
import time
import json
from io import StringIO

# Adjust path to import from the project root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from client.requests import (
    send_request,
    request_check_user_exists,
    request_register,
    request_login,
    request_set_profile,
    request_update_profile,
    request_get_profile,
    request_delete_messages,
    request_list_users,
    request_save_users,
    request_delete_profile,
    request_logout,
    request_get_membership
)
from common.protocol import (
    create_packet,
    parse_packet,
    REQ_CHE,
    REQ_REG,
    REQ_LOG,
    REQ_SET,
    REQ_UPA,
    REQ_GET,
    REQ_DME,
    REQ_ALL,
    REQ_SAV,
    REQ_DEL,
    REQ_BYE,
    REQ_MEM,
    RES_MEM,
    BUFFER_SIZE,
    CHE_TIME,
    USE_JSON,
    hash_password_sha256
)

# DummySocket to simulate a socket for testing purposes.
class DummySocket:
    def __init__(self, fake_response=b""):
        self.fake_response = fake_response
        self.sent_data = b""
        self.closed = False
    def sendall(self, data):
        self.sent_data += data
    def recv(self, bufsize):
        return self.fake_response
    def close(self):
        self.closed = True
    def settimeout(self, t):
        pass

class TestRequests(unittest.TestCase):

    def setUp(self):
        # Set CHE_TIME to False so timing prints do not interfere.
        global CHE_TIME
        CHE_TIME_backup = CHE_TIME
        CHE_TIME = False
        self.che_time_backup = CHE_TIME_backup

    def tearDown(self):
        global CHE_TIME
        CHE_TIME = self.che_time_backup

    def generate_fake_response(self, command, payload):
        # Use create_packet to generate a fake response packet.
        return create_packet(command, payload)

    def test_send_request_without_json(self):
        # Test send_request in non-JSON mode.
        # Prepare a fake response that send_request should receive.
        fake_response = self.generate_fake_response(REQ_CHE, "TestResponse")
        dummy = DummySocket(fake_response=fake_response)
        # Ensure USE_JSON is False
        global USE_JSON
        use_json_backup = USE_JSON
        USE_JSON = False

        cmd, payload, status = send_request(dummy, REQ_CHE, "TestPayload")
        self.assertEqual(cmd, REQ_CHE.rstrip(b'\x00'))
        self.assertEqual(payload, "TestResponse")
        self.assertEqual(status, b"___OK___")

        USE_JSON = use_json_backup

    def test_request_check_user_exists(self):
        # Fake response for REQ_CHE command
        fake_response = self.generate_fake_response(REQ_CHE, "Username exists.")
        dummy = DummySocket(fake_response=fake_response)
        cmd, payload, status = request_check_user_exists(dummy, "alice")
        self.assertEqual(cmd, REQ_CHE.rstrip(b'\x00'))
        self.assertEqual(payload, "Username exists.")

    def test_request_register(self):
        # Test that request_register sends correct data.
        # We simulate a response with a simple fake response.
        # Compute the hashed password
        username = "bob"
        password = "bobpass"
        hashed = hash_password_sha256(password)
        expected_payload = f"{username}|{hashed}"
        fake_response = self.generate_fake_response(REQ_REG, "Registration successful.")
        dummy = DummySocket(fake_response=fake_response)
        cmd, payload, status = request_register(dummy, username, password)
        self.assertEqual(cmd, REQ_REG.rstrip(b'\x00'))
        self.assertEqual(payload, "Registration successful.")
        # Check that the dummy socket got data containing our expected payload
        self.assertIn(expected_payload.encode(), dummy.sent_data)

    def test_request_login(self):
        username = "alice"
        password = "alicepass"
        hashed = hash_password_sha256(password)
        expected_payload = f"{username}|{hashed}"
        fake_response = self.generate_fake_response(REQ_LOG, "Login successful.")
        dummy = DummySocket(fake_response=fake_response)
        cmd, payload, status = request_login(dummy, username, password)
        self.assertEqual(cmd, REQ_LOG.rstrip(b'\x00'))
        self.assertEqual(payload, "Login successful.")
        self.assertIn(expected_payload.encode(), dummy.sent_data)

    def test_request_set_profile(self):
        username = "alice"
        message = "Hello, Bob!"
        target = "bob"
        expected_payload = f"{username}|{message}|{target}"
        fake_response = self.generate_fake_response(REQ_SET, "Message updated successfully.")
        dummy = DummySocket(fake_response=fake_response)
        cmd, payload, status = request_set_profile(dummy, username, message, target)
        self.assertEqual(cmd, REQ_SET.rstrip(b'\x00'))
        self.assertEqual(payload, "Message updated successfully.")
        self.assertIn(expected_payload.encode(), dummy.sent_data)

    def test_request_update_profile(self):
        username = "alice"
        fake_response = self.generate_fake_response(REQ_UPA, "User data updated successfully.")
        dummy = DummySocket(fake_response=fake_response)
        cmd, payload, status = request_update_profile(dummy, username)
        self.assertEqual(cmd, REQ_UPA.rstrip(b'\x00'))
        self.assertEqual(payload, "User data updated successfully.")

    def test_request_get_profile(self):
        username = "alice"
        fake_payload = "Message1\nMessage2"
        fake_response = self.generate_fake_response(REQ_GET, fake_payload)
        dummy = DummySocket(fake_response=fake_response)
        cmd, payload, status = request_get_profile(dummy, username)
        self.assertEqual(cmd, REQ_GET.rstrip(b'\x00'))
        self.assertEqual(payload, fake_payload)

    def test_request_delete_messages(self):
        username = "alice"
        message_id = "1"
        expected_payload = f"{username}|{message_id}"
        fake_response = self.generate_fake_response(REQ_DME, "Message deleted successfully.")
        dummy = DummySocket(fake_response=fake_response)
        cmd, payload, status = request_delete_messages(dummy, username, message_id)
        self.assertEqual(cmd, REQ_DME.rstrip(b'\x00'))
        self.assertEqual(payload, "Message deleted successfully.")
        self.assertIn(expected_payload.encode(), dummy.sent_data)

    def test_request_list_users(self):
        username = "alice"
        fake_response = self.generate_fake_response(REQ_ALL, "alice\nbob\ncharlie")
        dummy = DummySocket(fake_response=fake_response)
        cmd, payload, status = request_list_users(dummy, username)
        self.assertEqual(cmd, REQ_ALL.rstrip(b'\x00'))
        self.assertIn("alice", payload)
        self.assertIn("bob", payload)
        self.assertIn("charlie", payload)

    def test_request_save_users(self):
        username = "alice"
        fake_response = self.generate_fake_response(REQ_SAV, "User data saved successfully.")
        dummy = DummySocket(fake_response=fake_response)
        cmd, payload, status = request_save_users(dummy, username)
        self.assertEqual(cmd, REQ_SAV.rstrip(b'\x00'))
        self.assertEqual(payload, "User data saved successfully.")

    def test_request_delete_profile(self):
        username = "alice"
        fake_response = self.generate_fake_response(REQ_DEL, "User deleted successfully.")
        dummy = DummySocket(fake_response=fake_response)
        cmd, payload, status = request_delete_profile(dummy, username)
        self.assertEqual(cmd, REQ_DEL.rstrip(b'\x00'))
        self.assertEqual(payload, "User deleted successfully.")

    def test_request_logout(self):
        username = "alice"
        fake_response = self.generate_fake_response(REQ_BYE, f"👋 {username} You have logged out.")
        dummy = DummySocket(fake_response=fake_response)
        cmd, payload, status = request_logout(dummy, username)
        self.assertEqual(cmd, REQ_BYE.rstrip(b'\x00'))
        self.assertEqual(payload, f"👋 {username} You have logged out.")

    def test_request_get_membership(self):
        # Simulate a membership response with a JSON array.
        membership_data = [
            {"id": 1, "host": "127.0.0.1", "port": 9001},
            {"id": 2, "host": "127.0.0.1", "port": 9002}
        ]
        fake_response = self.generate_fake_response(REQ_MEM, json.dumps(membership_data))
        dummy = DummySocket(fake_response=fake_response)
        cmd, payload, status = request_get_membership(dummy)
        self.assertEqual(cmd, REQ_MEM.rstrip(b'\x00'))
        returned_membership = json.loads(payload)
        self.assertEqual(returned_membership, membership_data)

if __name__ == '__main__':
    unittest.main()
