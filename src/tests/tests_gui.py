import unittest
import json
import tkinter as tk
from tkinter import ttk, messagebox
import sys
import os

# Adjust path so we can import from project root.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from GUI.gui import ChatClientApp, LoginFrame, LandingFrame, ChatFrame
from client.requests import (
    request_check_user_exists,
    request_login,
    request_register,
    request_save_users,
    request_logout,
    request_list_users,
    request_get_profile,
    request_update_profile,
    request_set_profile,
    request_delete_messages,
    request_delete_profile,
    request_get_membership
)
from common.protocol import LEN_UNAME, LEN_PASSWORD, LEN_MESSAGE

# Create a dummy subclass of ChatClientApp that overrides network functions.
class DummyChatClientApp(ChatClientApp):
    def connect_to_cluster(self):
        # Instead of real connection, set a dummy socket and dummy membership.
        self.client_socket = "dummy_socket"
        self.cached_membership = [("127.0.0.1", 9001), ("127.0.0.1", 9002)]
        self.current_hostport = ("127.0.0.1", 9001)
        print("Dummy connect_to_cluster called. Cached membership set.")

    def failover(self):
        # Simulate failover by simply changing the current host to the next in the cached list.
        if self.cached_membership:
            self.current_hostport = self.cached_membership.pop(0)
            self.client_socket = "dummy_socket_after_failover"
            print(f"Dummy failover: new current hostport is {self.current_hostport}")
        else:
            print("No more servers available in dummy failover.")
            self.destroy()

    def send_request_with_failover(self, request_func, *args):
        # Use the request function name to simulate different responses.
        fname = request_func.__name__
        if fname == "request_check_user_exists":
            return (b"___OK___", "✅ Username exists.", b"___OK___")
        elif fname == "request_login":
            return (b"LOGIN___", "✅ Login successful.", b"___OK___")
        elif fname == "request_register":
            return (b"REGISTER", "✅ Registration successful.", b"___OK___")
        elif fname == "request_save_users":
            return (b"PERSIST_", "✅ User data saved successfully.", b"___OK___")
        elif fname == "request_logout":
            return (b"EXIT____", f"👋 {args[0]} You have logged out.", b"___OK___")
        elif fname == "request_list_users":
            return (b"ALLUSERS", "bob\ncharlie", b"___OK___")
        elif fname == "request_get_profile":
            return (b"GETPFILE", "UNREAD, Hello, bob", b"___OK___")
        elif fname == "request_update_profile":
            return (b"UPDATE__", "✅ User data updated successfully.", b"___OK___")
        elif fname == "request_set_profile":
            # Return a dummy success message.
            expected_payload = f"{args[0]}|{args[1]}|{args[2]}"
            return (b"SETPFILE", "✅ Message updated successfully.", b"___OK___")
        elif fname == "request_delete_messages":
            return (b"DELEMESG", "✅ Message deleted successfully.", b"___OK___")
        elif fname == "request_delete_profile":
            return (b"DELEUSER", "✅ User deleted successfully.", b"___OK___")
        elif fname == "request_get_membership":
            dummy_membership = [
                {"id": 1, "host": "127.0.0.1", "port": 9001},
                {"id": 2, "host": "127.0.0.1", "port": 9002}
            ]
            return (b"MEM_OK___", json.dumps(dummy_membership), b"___OK___")
        else:
            return (b"___OK___", "Default Response", b"___OK___")

# For convenience, define a dummy function to override validate_length (if needed)
def dummy_validate_length(input_str, max_length, field_name):
    return True

# Patch the is_ok function in gui.py to use our simple check.
def dummy_is_ok(response_value):
    if isinstance(response_value, bytes):
        return response_value.strip(b'\x00') == b"___OK___"
    elif isinstance(response_value, str):
        return response_value.strip() == "___OK___"
    return False

# Now create the test case for gui.py.
class TestGUI(unittest.TestCase):

    def setUp(self):
        # Set up a dummy Tkinter root.
        self.app = DummyChatClientApp()
        # Override validate_length with our dummy (or you can leave it if inputs are fine)
        self.app.validate_length = dummy_validate_length
        # Override is_ok in this module if needed
        global is_ok
        is_ok = dummy_is_ok

    def tearDown(self):
        # Destroy the Tkinter window to avoid hanging GUI instances.
        self.app.destroy()

    def test_connect_to_cluster(self):
        # Test that the dummy connection sets the client_socket and cached_membership.
        self.app.connect_to_cluster()
        self.assertEqual(self.app.client_socket, "dummy_socket")
        self.assertEqual(self.app.current_hostport, ("127.0.0.1", 9001))
        self.assertEqual(self.app.cached_membership, [("127.0.0.1", 9001), ("127.0.0.1", 9002)])

    def test_failover(self):
        # Test that failover changes the current_hostport.
        self.app.cached_membership = [("127.0.0.1", 9002)]
        self.app.current_hostport = ("127.0.0.1", 9001)
        self.app.failover()
        self.assertEqual(self.app.current_hostport, ("127.0.0.1", 9002))
        self.assertEqual(self.app.client_socket, "dummy_socket_after_failover")

    def test_send_request_with_failover(self):
        # Test that the dummy send_request_with_failover returns expected values.
        resp = self.app.send_request_with_failover(request_check_user_exists, "testuser")
        self.assertEqual(resp[0], b"___OK___")
        self.assertIn("✅ Username exists.", resp[1])
        resp = self.app.send_request_with_failover(request_get_membership)
        self.assertEqual(resp[0], b"MEM_OK___")
        membership = json.loads(resp[1])
        self.assertIsInstance(membership, list)
        self.assertGreaterEqual(len(membership), 1)

    def test_login_frame(self):
        # Test login functionality in LoginFrame.
        lf = self.app.login_frame
        # Simulate entering valid credentials.
        lf.entry_username.delete(0, tk.END)
        lf.entry_username.insert(0, "alice")
        lf.entry_password.delete(0, tk.END)
        lf.entry_password.insert(0, "alicepass")
        # Call login method.
        lf.login()
        # Check that the dummy send_request_with_failover for login was used.
        self.assertEqual(self.app.username, "alice")
        # Check that landing frame is now shown.
        self.assertTrue(self.app.landing_frame.winfo_ismapped())

    def test_register_frame(self):
        # Test registration functionality in LoginFrame.
        lf = self.app.login_frame
        lf.entry_username.delete(0, tk.END)
        lf.entry_username.insert(0, "newuser")
        lf.entry_password.delete(0, tk.END)
        lf.entry_password.insert(0, "newpass")
        lf.register()
        # Our dummy response returns success for registration.
        # Check that landing frame is not automatically shown for register.
        # (Typically after registration, you ask the user to log in.)
        self.assertIsNone(self.app.username)
        # Optionally, you can check the label_message for success message.
        self.assertIn("Account created", lf.label_message.cget("text"))

    def test_landing_frame_refresh(self):
        # Test that the LandingFrame refresh method populates the listbox.
        lf = self.app.landing_frame
        # Override the send_request_with_failover to simulate get_profile response.
        def dummy_get_profile(socket, username):
            return (b"GETPFILE", "UNREAD, Hello, bob\nREAD, Hi, bob", b"___OK___")
        self.app.send_request_with_failover = lambda func, *args: dummy_get_profile(None, args[0]) if func.__name__=="request_get_profile" else (b"___OK___", "Default", b"___OK___")
        lf.refresh()
        # Check that the listbox has items.
        self.assertGreater(lf.listbox.size(), 0)

    def test_chat_frame_open_chat(self):
        # Test that ChatFrame can open a chat tab for a recipient.
        cf = self.app.chat_frame
        # Ensure there is no conversation yet.
        self.assertEqual(len(cf.conversations), 0)
        # Open chat with recipient "bob"
        cf.open_chat("bob")
        self.assertIn("bob", cf.conversations)
        # The notebook should now have one tab.
        self.assertEqual(len(self.app.chat_frame.notebook.tabs()), 1)

    def test_logout_and_delete_account(self):
        # Test logout: simulate that a user is logged in and then logs out.
        self.app.username = "alice"
        # Overriding connect_to_cluster to set dummy socket for testing logout.
        self.app.connect_to_cluster = lambda: setattr(self.app, "client_socket", "dummy_socket")
        self.app.login_frame = self.app.login_frame  # already exists
        self.app.landing_frame = self.app.landing_frame
        lf = self.app.landing_frame
        lf.logout()
        self.assertIsNone(self.app.username)

if __name__ == '__main__':
    unittest.main()
