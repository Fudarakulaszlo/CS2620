import grpc
import json
import os
import sys
from concurrent import futures
import hashlib

# Add the parent directory to the module search path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common import chat_pb2_grpc, chat_pb2
USER_FILE = os.path.join("common/users.json")
MESSAGES_DIR = os.path.join("common/messages")

# Ensure message directory exists
os.makedirs(MESSAGES_DIR, exist_ok=True)
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    """Loads user data from file or initializes default user."""
    if not os.path.exists(USER_FILE):
        users = {"kakali121": hash_password("Yunlei1207~")}
        save_users(users)
        print("🆕 Created default user database.")
    else:
        with open(USER_FILE, "r") as f:
            users = json.load(f)
        print(f"🔐 Loaded {len(users)} users from database.")
    return users

def save_users(users):
    """Saves user data to file."""
    with open(USER_FILE, "w") as f:
        json.dump(users, f)
    print("💾 User data saved.")

class ChatService(chat_pb2_grpc.ChatServiceServicer):
    def __init__(self):
        self.users = load_users()
        self.messages = {}

    def CheckUserExists(self, request, context):
        """Handles `REQ_CHE` - Check if username exists."""
        print(f"🔍 Checking if user `{request.username}` exists...")
        exists = request.username in self.users
        print(f"✅ User exists: {exists}" if exists else "❌ User not found.")
        return chat_pb2.UserExistsResponse(exists=exists)

    def RegisterUser(self, request, context):
        """Handles `REQ_REG` - Register a new user."""
        print(f"📝 Registering user: {request.username}")
        if request.username in self.users:
            print("❌ Username already exists.")
            return chat_pb2.Response(status="ERROR", message="Username already exists.")
        
        self.users[request.username] = hash_password(request.password)
        save_users(self.users)

        # Create a message file for the user
        with open(os.path.join(MESSAGES_DIR, f"{request.username}.dat"), "w") as f:
            f.write("")

        print(f"✅ User `{request.username}` registered successfully.")
        return chat_pb2.Response(status="OK", message="Registration successful.")

    def LoginUser(self, request, context):
        """Handles `REQ_LOG` - Log in a user."""
        print(f"🔑 Logging in user: {request.username}")
        if request.username in self.users and self.users[request.username] == hash_password(request.password):
            print(f"✅ User `{request.username}` logged in successfully.")
            return chat_pb2.Response(status="OK", message="Login successful.")
        print("❌ Invalid credentials.")
        return chat_pb2.Response(status="ERROR", message="Invalid credentials.")

    def SendMessage(self, request, context):
        """Handles `REQ_SET` - Send a message."""
        print(f"📨 Sending message from `{request.sender}` to `{request.recipient}`: {request.message}")
        if request.recipient not in self.users:
            print("❌ Recipient not found.")
            return chat_pb2.Response(status="ERROR", message="Recipient not found.")

        sender_file = os.path.join(MESSAGES_DIR, f"{request.sender}.dat")
        recipient_file = os.path.join(MESSAGES_DIR, f"{request.recipient}.dat")

        with open(sender_file, "a") as f:
            f.write(f"SENT, {request.message}, {request.recipient}\n")
        with open(recipient_file, "a") as f:
            f.write(f"UNREAD, {request.message}, {request.sender}\n")

        print("✅ Message sent successfully.")
        return chat_pb2.Response(status="OK", message="Message sent.")

    def GetMessages(self, request, context):
        """Handles `REQ_GET` - Retrieve all messages for a user."""
        print(f"📩 Fetching messages for `{request.username}`...")
        user_file = os.path.join(MESSAGES_DIR, f"{request.username}.dat")
        try:
            with open(user_file, "r") as f:
                messages = f.readlines()
        except FileNotFoundError:
            print("❌ No messages found.")
            return chat_pb2.MessagesResponse(messages=["No messages found."])

        print(f"✅ Retrieved {len(messages)} messages.")
        return chat_pb2.MessagesResponse(messages=[msg.strip() for msg in messages])
    
    def GetUnreadMessages(self, request, context):
        """Handles `REQ_UNREAD` - Fetch unread messages only."""
        print(f"📩 Fetching unread messages for `{request.username}`...")
        user_file = os.path.join(MESSAGES_DIR, f"{request.username}.dat")

        if not os.path.exists(user_file):
            print("❌ No messages found.")
            return chat_pb2.MessagesResponse(messages=[])

        with open(user_file, "r") as f:
            messages = [msg.strip() for msg in f.readlines() if msg.startswith("UNREAD")]

        print(f"✅ Retrieved {len(messages)} unread messages.")
        return chat_pb2.MessagesResponse(messages=messages)

    def MarkMessagesRead(self, request, context):
        """Handles `REQ_UPA` - Mark all messages as read."""
        print(f"📩 Marking all messages as read for `{request.username}`...")
        user_file = os.path.join(MESSAGES_DIR, f"{request.username}.dat")

        if not os.path.exists(user_file):
            print("❌ No messages found.")
            return chat_pb2.Response(status="ERROR", message="No messages found.")

        with open(user_file, "r") as f:
            lines = f.readlines()
        
        with open(user_file, "w") as f:
            for line in lines:
                f.write(line.replace("UNREAD", "READ"))

        print(f"✅ All messages marked as read for `{request.username}`.")
        return chat_pb2.Response(status="OK", message="All messages marked as read.")

    def DeleteMessage(self, request, context):
        """Handles `REQ_DME` - Delete a specific message by index."""
        print(f"🗑 Deleting message `{request.message_id}` for user `{request.username}`...")
        user_file = os.path.join(MESSAGES_DIR, f"{request.username}.dat")
        try:
            with open(user_file, "r") as f:
                lines = f.readlines()
            with open(user_file, "w") as f:
                for i, line in enumerate(lines):
                    if i != request.message_id:
                        f.write(line)
            print("✅ Message deleted.")
            return chat_pb2.Response(status="OK", message="Message deleted.")
        except (FileNotFoundError, IndexError):
            print("❌ Message not found.")
            return chat_pb2.Response(status="ERROR", message="Message not found.")
        
    def ListUsers(self, request, context):
        """Handles `REQ_ALL` - List all registered users."""
        print("📋 Listing all users...")
        return chat_pb2.UserListResponse(users=list(self.users.keys()))

    def SaveData(self, request, context):
        """Handles `REQ_SAV` - Save all user data."""
        print("💾 Saving user data...")
        save_users(self.users)
        return chat_pb2.Response(status="OK", message="User data saved.")

    def DeleteUser(self, request, context):
        """Handles `REQ_DEL` - Delete a user account."""
        print(f"🚫 Deleting user `{request.username}`...")
        if request.username not in self.users:
            print("❌ User not found.")
            return chat_pb2.Response(status="ERROR", message="User not found.")

        del self.users[request.username]
        save_users(self.users)

        # Delete the user's message file
        user_file = os.path.join(MESSAGES_DIR, f"{request.username}.dat")
        os.remove(user_file)

        print(f"✅ User `{request.username}` deleted.")
        return chat_pb2.Response(status="OK", message="User deleted.")

    def LogoutUser(self, request, context):
        """Handles `REQ_BYE` - Logs out a user."""
        print(f"🚪 Logging out user `{request.username}`.")
        return chat_pb2.Response(status="OK", message=f"User `{request.username}` logged out.")

def serve():
    """Starts the gRPC server with keepalive settings."""
    options = [
        ("grpc.keepalive_time_ms", 10000),  
        ("grpc.keepalive_timeout_ms", 5000),  
        ("grpc.keepalive_permit_without_calls", 1),
        ("grpc.http2.max_pings_without_data", 0),
        ("grpc.http2.min_time_between_pings_ms", 5000),
        ("grpc.http2.min_ping_interval_without_data_ms", 5000)
    ]

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10), options=options)
    chat_pb2_grpc.add_ChatServiceServicer_to_server(ChatService(), server)
    server.add_insecure_port("[::]:50051")
    server.start()
    print("🚀 gRPC Server running on port 50051")
    server.wait_for_termination()
    
if __name__ == "__main__":
    serve()