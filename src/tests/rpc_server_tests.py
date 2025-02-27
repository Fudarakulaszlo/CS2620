import os
import json
import hashlib
import tempfile
import shutil
import unittest
from unittest.mock import patch, MagicMock, mock_open

# Import the server module. Replace 'chat_server' with your actual module name.
import chat_server

class TestChatServer(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for file operations
        self.test_dir = tempfile.mkdtemp()
        self.user_file = os.path.join(self.test_dir, "users.json")
        self.messages_dir = os.path.join(self.test_dir, "messages")
        os.makedirs(self.messages_dir, exist_ok=True)
        # Override module-level variables for isolation during tests
        chat_server.USER_FILE = self.user_file
        chat_server.MESSAGES_DIR = self.messages_dir

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_hash_password(self):
        password = "testpassword"
        expected_hash = hashlib.sha256(password.encode()).hexdigest()
        self.assertEqual(chat_server.hash_password(password), expected_hash)

    def test_load_users_creates_default_if_not_exists(self):
        # Ensure the user file does not exist.
        if os.path.exists(self.user_file):
            os.remove(self.user_file)
        with patch("builtins.print") as mock_print:
            users = chat_server.load_users()
        # Default user should be created.
        self.assertIn("kakali121", users)
        self.assertTrue(os.path.exists(self.user_file))
        mock_print.assert_any_call("🆕 Created default user database.")

    def test_save_users(self):
        users = {"user1": chat_server.hash_password("password1")}
        chat_server.save_users(users)
        with open(self.user_file, "r") as f:
            data = json.load(f)
        self.assertEqual(users, data)

    def test_check_user_exists(self):
        service = chat_server.ChatService()
        service.users = {"user1": chat_server.hash_password("password1")}
        # Create a dummy request with attribute username.
        request = MagicMock()
        request.username = "user1"
        response = service.CheckUserExists(request, None)
        self.assertTrue(response.exists)

        request.username = "nonexistent"
        response = service.CheckUserExists(request, None)
        self.assertFalse(response.exists)

    def test_register_user_success(self):
        service = chat_server.ChatService()
        service.users = {}  # Start with an empty user database.
        request = MagicMock()
        request.username = "newuser"
        request.password = "newpass"
        # Patch file creation via open so that actual disk writes occur in our temporary directory.
        with patch("builtins.open", mock_open()) as m_open:
            response = service.RegisterUser(request, None)
        self.assertEqual(response.status, "OK")
        self.assertEqual(response.message, "Registration successful.")
        self.assertIn("newuser", service.users)
        # Verify that the user's message file is created.
        user_message_file = os.path.join(self.messages_dir, "newuser.dat")
        self.assertTrue(os.path.exists(user_message_file))

    def test_register_user_failure(self):
        service = chat_server.ChatService()
        service.users = {"user1": chat_server.hash_password("pass")}
        request = MagicMock()
        request.username = "user1"
        request.password = "pass"
        response = service.RegisterUser(request, None)
        self.assertEqual(response.status, "ERROR")
        self.assertEqual(response.message, "Username already exists.")

    def test_login_user_success(self):
        service = chat_server.ChatService()
        service.users = {"user1": chat_server.hash_password("pass")}
        request = MagicMock()
        request.username = "user1"
        request.password = "pass"
        response = service.LoginUser(request, None)
        self.assertEqual(response.status, "OK")
        self.assertEqual(response.message, "Login successful.")

    def test_login_user_failure(self):
        service = chat_server.ChatService()
        service.users = {"user1": chat_server.hash_password("pass")}
        request = MagicMock()
        request.username = "user1"
        request.password = "wrong"
        response = service.LoginUser(request, None)
        self.assertEqual(response.status, "ERROR")
        self.assertEqual(response.message, "Invalid credentials.")

    def test_send_message_success(self):
        service = chat_server.ChatService()
        # Set up both sender and recipient in the user database.
        service.users = {
            "sender": chat_server.hash_password("pass"),
            "recipient": chat_server.hash_password("pass")
        }
        # Create message files for both users.
        sender_file = os.path.join(self.messages_dir, "sender.dat")
        recipient_file = os.path.join(self.messages_dir, "recipient.dat")
        with open(sender_file, "w") as f:
            f.write("")
        with open(recipient_file, "w") as f:
            f.write("")
        request = MagicMock()
        request.sender = "sender"
        request.recipient = "recipient"
        request.message = "Hello"
        response = service.SendMessage(request, None)
        self.assertEqual(response.status, "OK")
        self.assertEqual(response.message, "Message sent.")
        with open(sender_file, "r") as f:
            content_sender = f.read()
        self.assertIn("SENT, Hello, recipient", content_sender)
        with open(recipient_file, "r") as f:
            content_recipient = f.read()
        self.assertIn("UNREAD, Hello, sender", content_recipient)

    def test_send_message_failure_invalid_recipient(self):
        service = chat_server.ChatService()
        service.users = {"sender": chat_server.hash_password("pass")}
        request = MagicMock()
        request.sender = "sender"
        request.recipient = "nonexistent"
        request.message = "Hello"
        response = service.SendMessage(request, None)
        self.assertEqual(response.status, "ERROR")
        self.assertEqual(response.message, "Recipient not found.")

    def test_get_messages(self):
        service = chat_server.ChatService()
        username = "user1"
        user_file = os.path.join(self.messages_dir, f"{username}.dat")
        with open(user_file, "w") as f:
            f.write("Test message 1\nTest message 2\n")
        request = MagicMock()
        request.username = username
        response = service.GetMessages(request, None)
        self.assertEqual(response.messages, ["Test message 1", "Test message 2"])

    def test_get_messages_file_not_found(self):
        service = chat_server.ChatService()
        username = "nonexistent"
        request = MagicMock()
        request.username = username
        response = service.GetMessages(request, None)
        self.assertEqual(response.messages, ["No messages found."])

    def test_get_unread_messages(self):
        service = chat_server.ChatService()
        username = "user1"
        user_file = os.path.join(self.messages_dir, f"{username}.dat")
        with open(user_file, "w") as f:
            f.write("UNREAD, Hello, sender\nREAD, Hi, sender\nUNREAD, How are you?, sender\n")
        request = MagicMock()
        request.username = username
        response = service.GetUnreadMessages(request, None)
        # Only lines beginning with "UNREAD" should be returned.
        self.assertEqual(len(response.messages), 2)
        self.assertTrue(all(msg.startswith("UNREAD") for msg in response.messages))

    def test_mark_messages_read(self):
        service = chat_server.ChatService()
        username = "user1"
        user_file = os.path.join(self.messages_dir, f"{username}.dat")
        original = "UNREAD, Hello, sender\nUNREAD, Hi, sender\n"
        with open(user_file, "w") as f:
            f.write(original)
        request = MagicMock()
        request.username = username
        response = service.MarkMessagesRead(request, None)
        self.assertEqual(response.status, "OK")
        self.assertEqual(response.message, "All messages marked as read.")
        with open(user_file, "r") as f:
            lines = f.readlines()
        for line in lines:
            self.assertIn("READ", line)
            self.assertNotIn("UNREAD", line)

    def test_delete_message_success(self):
        service = chat_server.ChatService()
        username = "user1"
        user_file = os.path.join(self.messages_dir, f"{username}.dat")
        messages = ["Msg1\n", "Msg2\n", "Msg3\n"]
        with open(user_file, "w") as f:
            f.writelines(messages)
        request = MagicMock()
        request.username = username
        request.message_id = 1  # Delete second message.
        response = service.DeleteMessage(request, None)
        self.assertEqual(response.status, "OK")
        self.assertEqual(response.message, "Message deleted.")
        with open(user_file, "r") as f:
            remaining = f.readlines()
        self.assertEqual(len(remaining), 2)
        self.assertEqual(remaining[0], messages[0])
        self.assertEqual(remaining[1], messages[2])

    def test_delete_message_failure(self):
        service = chat_server.ChatService()
        username = "user1"
        # Create an empty message file.
        user_file = os.path.join(self.messages_dir, f"{username}.dat")
        with open(user_file, "w") as f:
            f.write("")
        request = MagicMock()
        request.username = username
        request.message_id = 0
        response = service.DeleteMessage(request, None)
        self.assertEqual(response.status, "ERROR")
        self.assertEqual(response.message, "Message not found.")

    def test_list_users(self):
        service = chat_server.ChatService()
        service.users = {
            "user1": chat_server.hash_password("pass"),
            "user2": chat_server.hash_password("pass")
        }
        request = MagicMock()
        response = service.ListUsers(request, None)
        self.assertCountEqual(response.users, ["user1", "user2"])

    def test_save_data(self):
        service = chat_server.ChatService()
        service.users = {"user1": chat_server.hash_password("pass")}
        with patch('chat_server.save_users') as mock_save:
            request = MagicMock()
            response = service.SaveData(request, None)
            mock_save.assert_called_once_with(service.users)
        self.assertEqual(response.status, "OK")
        self.assertEqual(response.message, "User data saved.")

    def test_delete_user_success(self):
        service = chat_server.ChatService()
        service.users = {"user1": chat_server.hash_password("pass")}
        # Create a dummy message file for the user.
        user_file = os.path.join(self.messages_dir, "user1.dat")
        with open(user_file, "w") as f:
            f.write("Test message")
        request = MagicMock()
        request.username = "user1"
        with patch("os.remove") as mock_remove:
            response = service.DeleteUser(request, None)
            mock_remove.assert_called_once_with(user_file)
        self.assertEqual(response.status, "OK")
        self.assertEqual(response.message, "User deleted.")
        self.assertNotIn("user1", service.users)

    def test_delete_user_failure(self):
        service = chat_server.ChatService()
        service.users = {"user1": chat_server.hash_password("pass")}
        request = MagicMock()
        request.username = "nonexistent"
        response = service.DeleteUser(request, None)
        self.assertEqual(response.status, "ERROR")
        self.assertEqual(response.message, "User not found.")

    def test_logout_user(self):
        service = chat_server.ChatService()
        request = MagicMock()
        request.username = "user1"
        response = service.LogoutUser(request, None)
        self.assertEqual(response.status, "OK")
        self.assertIn("logged out", response.message)

if __name__ == "__main__":
    unittest.main()
