import unittest
import tempfile
import os
import json
import shutil
from io import StringIO
from common.protocol import (
    RES_OK,
    RES_ERR_NO_USER,
    RES_ERR_USER_EXISTS,
    RES_ERR_LOGIN,
    hash_password_sha256,
    verify_password
)
from server.responses import (
    set_node_id,
    send_response,
    handle_check_user_exists,
    handle_reg,
    handle_log,
    handle_set,
    handle_update,
    handle_get,
    handle_delemsg,
    handle_all,
    handle_sav,
    handle_delete,
    handle_bye,
    NODE_ID,
    MESSAGES_DIR,
    USERS_FILE
)

# Dummy socket that captures sent data.
class DummySocket:
    def __init__(self):
        self.data = b""
        self.closed = False
    def sendall(self, data):
        self.data += data
    def close(self):
        self.closed = True

# Utility function to reset global paths in responses.py for testing.
def init_temp_env(node_id, base_dir):
    # Set environment so that MESSAGES_DIR and USERS_FILE are inside our temporary directory.
    # We'll mimic what set_node_id does, but direct it to our temp folder.
    global MESSAGES_DIR, USERS_FILE
    set_node_id(node_id)
    # Overwrite the paths with ones inside our temp directory.
    MESSAGES_DIR = os.path.join(base_dir, "messages", f"node_{node_id}")
    os.makedirs(MESSAGES_DIR, exist_ok=True)
    users_dir = os.path.join(base_dir, "users")
    os.makedirs(users_dir, exist_ok=True)
    USERS_FILE = os.path.join(users_dir, f"node_{node_id}_users.dat")

class TestResponses(unittest.TestCase):

    def setUp(self):
        # Create a temporary directory for testing files.
        self.test_dir = tempfile.mkdtemp()
        # Initialize the node-specific directories in the temp directory.
        init_temp_env(99, self.test_dir)
        # Create a dummy socket for capturing responses.
        self.dummy_socket = DummySocket()
        # Create a test users dictionary.
        self.users = {"alice": hash_password_sha256("alicepass")}
        
    def tearDown(self):
        # Remove temporary directory after test.
        shutil.rmtree(self.test_dir)

    def test_send_response_json_false(self):
        # Test send_response when USE_JSON is False
        from common.protocol import USE_JSON
        USE_JSON_backup = USE_JSON
        try:
            # Force non-JSON mode
            USE_JSON = False
            send_response(self.dummy_socket, RES_OK, "Test OK")
            # Now parse what was sent using create_packet from protocol.py
            # Since our test doesn't reparse the packet, we at least check our dummy socket got some data.
            self.assertTrue(len(self.dummy_socket.data) > 0)
        finally:
            USE_JSON = USE_JSON_backup

    def test_handle_check_user_exists_true(self):
        # When user exists, handle_check_user_exists should send RES_OK response.
        result = handle_check_user_exists(self.dummy_socket, self.users, "alice")
        self.assertTrue(result)
        # Check that the response data contains "Username exists"
        self.assertIn("✅ Username exists.", self.dummy_socket.data.decode())

    def test_handle_check_user_exists_false(self):
        # When user does not exist, it should send RES_ERR_NO_USER
        self.dummy_socket.data = b""
        result = handle_check_user_exists(self.dummy_socket, self.users, "bob")
        self.assertFalse(result)
        self.assertIn("❌ Username not found.", self.dummy_socket.data.decode())

    def test_handle_reg_success(self):
        # Register a new user "bob" and check that his message file is created.
        self.dummy_socket.data = b""
        result = handle_reg(self.dummy_socket, self.users, "bob", "bobpass")
        self.assertTrue(result)
        # Check response text contains "Registration successful"
        self.assertIn("✅ Registration successful.", self.dummy_socket.data.decode())
        # Verify that bob was added to the users dictionary
        self.assertIn("bob", self.users)
        # Check that a file named "bob.dat" exists in the messages directory.
        bob_file = os.path.join(MESSAGES_DIR, "bob.dat")
        self.assertTrue(os.path.exists(bob_file))

    def test_handle_reg_failure(self):
        # Attempt to register an existing user "alice"
        self.dummy_socket.data = b""
        result = handle_reg(self.dummy_socket, self.users, "alice", "newpass")
        self.assertFalse(result)
        self.assertIn("❌ Username already exists.", self.dummy_socket.data.decode())

    def test_handle_log_success(self):
        # Test login with correct credentials.
        self.dummy_socket.data = b""
        result = handle_log(self.dummy_socket, self.users, "alice", "alicepass")
        self.assertTrue(result)
        self.assertIn("✅ Login successful.", self.dummy_socket.data.decode())

    def test_handle_log_failure(self):
        # Test login with incorrect password.
        self.dummy_socket.data = b""
        result = handle_log(self.dummy_socket, self.users, "alice", "wrongpass")
        self.assertFalse(result)
        self.assertIn("❌ Invalid credentials.", self.dummy_socket.data.decode())

    def test_handle_set_and_get(self):
        # First, register two users if needed.
        # "alice" already exists; register "bob"
        handle_reg(None, self.users, "bob", "bobpass")
        # Clear dummy socket data
        self.dummy_socket.data = b""
        # Test handle_set: send a message from alice to bob.
        handle_set(self.dummy_socket, self.users, "alice", "Hello Bob!", "bob")
        self.assertIn("✅ Message updated successfully.", self.dummy_socket.data.decode())
        # Now test handle_get for bob; expect to see an "UNREAD" message from alice.
        dummy_get = DummySocket()
        handle_get(dummy_get, self.users, "bob")
        response = dummy_get.data.decode()
        self.assertIn("UNREAD", response)
        self.assertIn("Hello Bob!", response)

    def test_handle_update(self):
        # Write a sample messages file for a user with an UNREAD message.
        user_file = os.path.join(MESSAGES_DIR, "alice.dat")
        with open(user_file, "w") as f:
            f.write("UNREAD, Hello, bob\n")
        self.dummy_socket.data = b""
        handle_update(self.dummy_socket, self.users, "alice")
        self.assertIn("✅ User data updated successfully.", self.dummy_socket.data.decode())
        # Now check that the file content has "READ" instead of "UNREAD"
        with open(user_file, "r") as f:
            content = f.read()
        self.assertNotIn("UNREAD", content)
        self.assertIn("READ", content)

    def test_handle_delemsg(self):
        # Create a messages file with multiple lines for user "alice"
        user_file = os.path.join(MESSAGES_DIR, "alice.dat")
        messages = ["SENT, Hello, bob", "UNREAD, How are you?, bob", "SENT, Fine, bob"]
        with open(user_file, "w") as f:
            for line in messages:
                f.write(line + "\n")
        self.dummy_socket.data = b""
        # Delete the message at index 1 (the second message)
        handle_delemsg(self.dummy_socket, self.users, "alice", "1")
        self.assertIn("✅ Message deleted successfully.", self.dummy_socket.data.decode())
        # Now check that the file has 2 lines instead of 3
        with open(user_file, "r") as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 2)

    def test_handle_all(self):
        # Test handle_all returns a list of usernames
        self.dummy_socket.data = b""
        handle_all(self.dummy_socket, self.users, "alice")
        response = self.dummy_socket.data.decode()
        # Our users dict should contain at least "alice"
        self.assertIn("alice", response)

    def test_handle_sav(self):
        # Test handle_sav writes the users dictionary to USERS_FILE.
        if os.path.exists(USERS_FILE):
            os.remove(USERS_FILE)
        self.dummy_socket.data = b""
        handle_sav(self.dummy_socket, self.users)
        self.assertTrue(os.path.exists(USERS_FILE))
        with open(USERS_FILE, "r") as f:
            data = json.load(f)
        self.assertEqual(data, self.users)
        self.assertIn("✅ User data saved successfully.", self.dummy_socket.data.decode())

    def test_handle_delete(self):
        # Test deleting a user from the users dictionary and its messages file.
        # First, register a new user "charlie"
        handle_reg(self.dummy_socket, self.users, "charlie", "charliepass")
        charlie_file = os.path.join(MESSAGES_DIR, "charlie.dat")
        self.assertTrue(os.path.exists(charlie_file))
        self.dummy_socket.data = b""
        handle_delete(self.dummy_socket, self.users, "charlie")
        self.assertIn("✅ User deleted successfully.", self.dummy_socket.data.decode())
        self.assertNotIn("charlie", self.users)
        self.assertFalse(os.path.exists(charlie_file))

    def test_handle_bye(self):
        # Test that handle_bye sends a goodbye message and closes the socket.
        self.dummy_socket.data = b""
        handle_bye(self.dummy_socket, "alice")
        self.assertIn("👋 alice You have logged out.", self.dummy_socket.data.decode())
        self.assertTrue(self.dummy_socket.closed)

if __name__ == '__main__':
    unittest.main()
