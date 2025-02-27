import unittest
from unittest.mock import patch, MagicMock
import grpc
import sys
import os

# Import the functions to test.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import client.client_rpc as client

# A simple dummy response class to simulate gRPC responses.
class DummyResponse:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class TestChatClient(unittest.TestCase):

    @patch('client.chat_pb2_grpc.ChatServiceStub')
    @patch('client.grpc.insecure_channel')
    def test_connect_to_server(self, mock_insecure_channel, mock_stub_class):
        # Arrange: set up a dummy channel and stub.
        dummy_channel = MagicMock()
        mock_insecure_channel.return_value = dummy_channel
        dummy_stub = MagicMock()
        mock_stub_class.return_value = dummy_stub

        # Act: call the function under test.
        stub = client.connect_to_server()

        # Assert: verify that insecure_channel is called with expected options
        mock_insecure_channel.assert_called_once_with(
            "localhost:50051",
            options=[
                ("grpc.keepalive_time_ms", 10000),
                ("grpc.keepalive_timeout_ms", 5000),
                ("grpc.keepalive_permit_without_calls", 1),
                ("grpc.http2.max_pings_without_data", 0),
                ("grpc.http2.min_time_between_pings_ms", 5000),
                ("grpc.http2.min_ping_interval_without_data_ms", 5000)
            ]
        )
        # And that the stub is created using the dummy channel.
        mock_stub_class.assert_called_once_with(dummy_channel)
        self.assertEqual(stub, dummy_stub)

    @patch('builtins.input')
    def test_authenticate_existing_user_successful_login(self, mock_input):
        # Arrange: simulate user input for an existing user login.
        # First input returns username, second returns password.
        mock_input.side_effect = ["user1", "pass1"]

        stub = MagicMock()
        # Simulate that the username exists.
        stub.CheckUserExists.return_value = DummyResponse(exists=True)
        # Simulate a successful login.
        stub.LoginUser.return_value = DummyResponse(status="OK")

        # Act
        returned_stub, username = client.authenticate(stub)

        # Assert
        self.assertEqual(username, "user1")
        stub.CheckUserExists.assert_called_once()
        stub.LoginUser.assert_called_once()

    @patch('builtins.input')
    def test_authenticate_new_user_registration(self, mock_input):
        # Arrange: simulate the flow for a non-existing user.
        # First input: username that does not exist.
        # Then new username and password for registration.
        mock_input.side_effect = ["newuser", "newuser", "newpass"]

        stub = MagicMock()
        # Simulate that the username does not exist.
        stub.CheckUserExists.return_value = DummyResponse(exists=False)
        # Simulate a successful registration.
        stub.RegisterUser.return_value = DummyResponse(status="OK")

        # Act
        returned_stub, username = client.authenticate(stub)

        # Assert
        self.assertEqual(username, "newuser")
        stub.CheckUserExists.assert_called_once()
        stub.RegisterUser.assert_called_once()

    @patch('builtins.print')
    def test_get_messages_with_messages(self, mock_print):
        # Arrange
        stub = MagicMock()
        messages_list = ["Hello", "World"]
        stub.GetMessages.return_value = DummyResponse(messages=messages_list)

        # Act
        result = client.get_messages(stub, "user1")

        # Assert
        self.assertEqual(result, messages_list)
        mock_print.assert_any_call("\n📩 Messages for user1:")

    @patch('builtins.input')
    @patch('builtins.print')
    def test_send_message_valid_recipient(self, mock_print, mock_input):
        # Arrange: simulate listing of users and valid recipient/message input.
        stub = MagicMock()
        stub.ListUsers.return_value = DummyResponse(users=["user1", "user2"])
        mock_input.side_effect = ["user2", "Hello there"]

        # Act
        client.send_message(stub, "user1")

        # Assert: check that SendMessage was called with a request having correct attributes.
        stub.SendMessage.assert_called_once()
        request = stub.SendMessage.call_args[0][0]
        self.assertEqual(request.sender, "user1")
        self.assertEqual(request.recipient, "user2")
        self.assertEqual(request.message, "Hello there")

    @patch('builtins.input')
    @patch('builtins.print')
    def test_send_message_invalid_recipient(self, mock_print, mock_input):
        # Arrange: simulate listing of users and an invalid recipient input.
        stub = MagicMock()
        stub.ListUsers.return_value = DummyResponse(users=["user1", "user2"])
        mock_input.side_effect = ["nonexistent"]

        # Act
        client.send_message(stub, "user1")

        # Assert: SendMessage should not be called.
        stub.SendMessage.assert_not_called()
        mock_print.assert_any_call("❌ User not found. Try again.")

    @patch('builtins.print')
    def test_view_new_messages(self, mock_print):
        # Arrange: simulate unread messages.
        stub = MagicMock()
        unread_msgs = ["New message 1", "New message 2"]
        stub.GetUnreadMessages.return_value = DummyResponse(messages=unread_msgs)

        # Act
        client.view_new_messages(stub, "user1")

        # Assert: check output and that MarkMessagesRead was called.
        mock_print.assert_any_call("📩 Fetching 2 UNREAD message(s)...")
        stub.MarkMessagesRead.assert_called_once_with(client.chat_pb2.UsernameRequest(username="user1"))

    @patch('builtins.input')
    @patch('builtins.print')
    def test_delete_message_valid_index(self, mock_print, mock_input):
        # Arrange: simulate get_messages returning three messages.
        stub = MagicMock()
        messages_list = ["Msg1", "Msg2", "Msg3"]
        stub.GetMessages.return_value = DummyResponse(messages=messages_list)
        # Simulate valid input index "2" (which corresponds to index 1 in zero-indexing).
        mock_input.side_effect = ["2"]

        # Act
        client.delete_message(stub, "user1")

        # Assert: DeleteMessage should be called with message_id = 1.
        stub.DeleteMessage.assert_called_once()
        request = stub.DeleteMessage.call_args[0][0]
        self.assertEqual(request.username, "user1")
        self.assertEqual(request.message_id, 1)

    @patch('builtins.input')
    @patch('builtins.print')
    def test_delete_message_invalid_index(self, mock_print, mock_input):
        # Arrange: simulate get_messages returning two messages.
        stub = MagicMock()
        messages_list = ["Msg1", "Msg2"]
        stub.GetMessages.return_value = DummyResponse(messages=messages_list)
        # Simulate an invalid index input.
        mock_input.side_effect = ["5"]

        # Act
        client.delete_message(stub, "user1")

        # Assert: DeleteMessage should not be called.
        stub.DeleteMessage.assert_not_called()
        mock_print.assert_any_call("❌ Invalid index. Try again.")

    @patch('builtins.input')
    @patch('builtins.print')
    def test_delete_account_confirm(self, mock_print, mock_input):
        # Arrange: simulate confirmation for account deletion.
        stub = MagicMock()
        mock_input.return_value = "yes"
        stub.DeleteUser.return_value = DummyResponse(message="Account deleted successfully")

        # Act
        client.delete_account(stub, "user1")

        # Assert: DeleteUser should be called with the proper UsernameRequest.
        stub.DeleteUser.assert_called_once_with(client.chat_pb2.UsernameRequest(username="user1"))
        mock_print.assert_any_call("Account deleted successfully")

    @patch('builtins.input')
    @patch('builtins.print')
    def test_delete_account_cancel(self, mock_print, mock_input):
        # Arrange: simulate cancellation of account deletion.
        stub = MagicMock()
        mock_input.return_value = "no"

        # Act
        client.delete_account(stub, "user1")

        # Assert: DeleteUser should not be called and a cancellation message is printed.
        stub.DeleteUser.assert_not_called()
        mock_print.assert_any_call("❌ Account deletion cancelled.")

if __name__ == '__main__':
    unittest.main()
