import os
import sys
import grpc

# Add the parent directory to the module search path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import common.chat_pb2
import common.chat_pb2_grpc

def run():
    channel = grpc.insecure_channel("localhost:50051")
    stub = chat_pb2_grpc.ChatServiceStub(channel)

    username = input("Enter your username: ").strip()
    response = stub.CheckUserExists(chat_pb2.UsernameRequest(username=username))

    if response.exists:
        password = input("Enter your password: ").strip()
        login_response = stub.LoginUser(chat_pb2.LoginRequest(username=username, password=password))
        print(login_response.message)
    else:
        print("User not found. Registering new user...")
        username = input("Enter a new username: ").strip()
        password = input("Enter a new password: ").strip()
        reg_response = stub.RegisterUser(chat_pb2.RegisterRequest(username=username, password=password))
        print(reg_response.message)

if __name__ == "__main__":
    run()