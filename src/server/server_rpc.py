import grpc
import json
import os
import sys
from concurrent import futures
import hashlib
# Add the parent directory to the module search path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import common.chat_pb2
import common.chat_pb2_grpc

USER_FILE = "users.json"

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    if not os.path.exists(USER_FILE):
        return {}
    with open(USER_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USER_FILE, "w") as f:
        json.dump(users, f)

class ChatService(chat_pb2_grpc.ChatServiceServicer):
    def __init__(self):
        self.users = load_users()
        self.messages = {}  # Store messages in memory

    def CheckUserExists(self, request, context):
        exists = request.username in self.users
        return chat_pb2.UserExistsResponse(exists=exists)

    def RegisterUser(self, request, context):
        if request.username in self.users:
            return chat_pb2.Response(status="ERROR", message="Username already exists.")
        self.users[request.username] = hash_password(request.password)
        save_users(self.users)
        return chat_pb2.Response(status="OK", message="Registration successful.")

    def LoginUser(self, request, context):
        if request.username in self.users and self.users[request.username] == hash_password(request.password):
            return chat_pb2.Response(status="OK", message="Login successful.")
        return chat_pb2.Response(status="ERROR", message="Invalid credentials.")

    def SendMessage(self, request, context):
        if request.recipient not in self.messages:
            self.messages[request.recipient] = []
        self.messages[request.recipient].append(f"{request.sender}: {request.message}")
        return chat_pb2.Response(status="OK", message="Message sent.")

    def GetMessages(self, request, context):
        messages = self.messages.get(request.username, [])
        return chat_pb2.MessagesResponse(messages=messages)

    def DeleteMessage(self, request, context):
        if request.username in self.messages and len(self.messages[request.username]) > request.message_id:
            del self.messages[request.username][request.message_id]
            return chat_pb2.Response(status="OK", message="Message deleted.")
        return chat_pb2.Response(status="ERROR", message="Message not found.")

    def ListUsers(self, request, context):
        return chat_pb2.UserListResponse(users=list(self.users.keys()))

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    chat_pb2_grpc.add_ChatServiceServicer_to_server(ChatService(), server)
    server.add_insecure_port("[::]:50051")
    server.start()
    print("🚀 gRPC Server running on port 50051...")
    server.wait_for_termination()

if __name__ == "__main__":
    serve()