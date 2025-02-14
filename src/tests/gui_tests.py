"""
* File: gui_tests.py
* Author: Áron Vékássy, Karen Li
*
* This file contains unit tests for the Tkinter-based GUI client.
"""

import unittest
from unittest.mock import patch, MagicMock
import tkinter as tk
import sys
import os
import json

# Adjust the path so that the "GUI" package is found.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import GUI.gui as gui  # Import the GUI module under test

# A dummy socket that mimics a real socket.
class DummySocket:
    def __init__(self):
        self.last_sent = None

    def sendall(self, data):
        self.last_sent = data  # Store the last data sent

    def recv(self, bufsize):
        # Return a dummy JSON-encoded response that simulates a successful GET request.
        dummy_response = {
            "cmd": "GET",
            "payload": "", 
            "status": "___OK___"
        }
        return json.dumps(dummy_response).encode('utf-8')

    def close(self):
        pass

# Test the connect_to_server function in isolation.
class TestConnectToServer(unittest.TestCase):
    @patch('GUI.gui.socket.socket')
    def test_connect_to_server_success(self, mock_socket_class):
        # Create a dummy socket instance and simulate a successful connection.
        dummy_socket_instance = MagicMock()
        dummy_socket_instance.connect.return_value = None
        mock_socket_class.return_value = dummy_socket_instance

        client_sock = gui.connect_to_server()
        self.assertIsNotNone(client_sock)
        dummy_socket_instance.connect.assert_called_once_with((gui.HOST, gui.PORT))


# Tests for the GUI functionality.
class TestGUI(unittest.TestCase):

    def setUp(self):
        # Patch connect_to_server so that ChatClientApp uses a DummySocket.
        self.connect_patch = patch('GUI.gui.connect_to_server', return_value=DummySocket())
        self.mock_connect = self.connect_patch.start()
        # Instantiate the ChatClientApp (a subclass of tk.Tk).
        self.app = gui.ChatClientApp()
        # Hide the window so it doesn't appear during tests.
        self.app.withdraw()

    def tearDown(self):
        self.connect_patch.stop()
        self.app.destroy()

    def test_is_ok_bytes(self):
        self.assertTrue(gui.is_ok(b"___OK___"))
        self.assertFalse(gui.is_ok(b"ERROR"))

    def test_is_ok_str(self):
        self.assertTrue(gui.is_ok("___OK___"))
        self.assertFalse(gui.is_ok("ERROR"))

    @patch('GUI.gui.request_check_user_exists')
    @patch('GUI.gui.request_login')
    def test_login_success(self, mock_request_login, mock_request_check_user_exists):
        # Simulate that the user exists and login is successful.
        mock_request_check_user_exists.return_value = (b"___OK___", "", "")
        mock_request_login.return_value = (b"___OK___", "", "")

        # Insert valid credentials into the login frame's entry widgets.
        self.app.login_frame.entry_username.insert(0, "Alice")
        self.app.login_frame.entry_password.insert(0, "password")
        # Replace the show_landing_frame method with a dummy to capture its call.
        self.app.show_landing_frame = MagicMock()

        # Invoke the login method.
        self.app.login_frame.login()

        # Check that the username was stored and landing frame was triggered.
        self.assertEqual(self.app.username, "Alice")
        self.app.show_landing_frame.assert_called_once()
        # Verify that the login frame's label shows a success message.
        self.assertEqual(self.app.login_frame.label_message["text"], "Login successful!")
        self.assertEqual(self.app.login_frame.label_message["fg"], "green")

    @patch('GUI.gui.request_check_user_exists')
    def test_login_user_not_exists(self, mock_request_check_user_exists):
        # Simulate that the user does not exist.
        mock_request_check_user_exists.return_value = (b"ERROR", "", "")

        self.app.login_frame.entry_username.insert(0, "Bob")
        self.app.login_frame.entry_password.insert(0, "password")
        self.app.login_frame.login()

        self.assertEqual(self.app.login_frame.label_message["text"],
                         "User does not exist. Please register.")

    @patch('GUI.gui.request_check_user_exists')
    @patch('GUI.gui.request_register')
    @patch('GUI.gui.request_save_users')
    def test_register_success(self, mock_request_save_users, mock_request_register, mock_request_check_user_exists):
        # Simulate that the user does not exist (so registration is allowed).
        mock_request_check_user_exists.return_value = (b"ERROR", "", "")
        mock_request_register.return_value = (b"___OK___", "", "")
        mock_request_save_users.return_value = (b"___OK___", "", "")

        self.app.login_frame.entry_username.insert(0, "Carol")
        self.app.login_frame.entry_password.insert(0, "password")
        self.app.login_frame.register()

        self.assertEqual(self.app.login_frame.label_message["text"],
                         "Account created. Please login.")
        self.assertEqual(self.app.login_frame.label_message["fg"], "green")

    @patch('GUI.gui.request_list_users')
    def test_update_new_recipient_menu(self, mock_request_list_users):
        # Simulate a response containing a list of users.
        mock_request_list_users.return_value = ("", "Alice\nBob\nCarol")
        self.app.username = "Alice"
        self.app.landing_frame.update_new_recipient_menu()

        # The new_recipient_var should be set to the first user that is not "Alice"
        self.assertEqual(self.app.landing_frame.new_recipient_var.get(), "Bob")

    @patch('GUI.gui.request_set_profile')
    @patch('GUI.gui.validate_length', return_value=True)
    def test_send_message(self, mock_validate_length, mock_request_set_profile):
        # Setup ChatFrame: set the current user and recipient.
        self.app.username = "Alice"
        self.app.chat_frame.recipient_var.set("Bob")
        # Insert a test message.
        self.app.chat_frame.message_entry.insert("1.0", "Hello, Bob!")

        # Simulate that a conversation with "Bob" already exists.
        norm_recipient = "bob"
        frame = tk.Frame(self.app.chat_frame.notebook)
        listbox = tk.Listbox(frame)
        listbox.pack()
        # IMPORTANT: add the frame as a tab in the notebook.
        self.app.chat_frame.notebook.add(frame, text="Bob")
        self.app.chat_frame.conversations[norm_recipient] = {
            "frame": frame,
            "listbox": listbox,
            "message_indices": {},
            "display": "Bob"
        }

        # Call send_message.
        self.app.chat_frame.send_message()

        # Verify that request_set_profile was called with the expected parameters.
        mock_request_set_profile.assert_called_once_with(
            self.app.client_socket, "Alice", "Hello, Bob!", "Bob"
        )
        # Verify that the message text area has been cleared.
        self.assertEqual(self.app.chat_frame.message_entry.get("1.0", "end").strip(), "")

if __name__ == '__main__':
    unittest.main()
