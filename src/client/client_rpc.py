import os
import sys
import grpc

# Add the parent directory to the module search path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common import chat_pb2
from common import chat_pb2_grpc

def connect_to_server():
    """Establishes a connection to the gRPC server with keepalive settings."""
    options = [
        ("grpc.keepalive_time_ms", 10000),  
        ("grpc.keepalive_timeout_ms", 5000),  
        ("grpc.keepalive_permit_without_calls", 1), 
        ("grpc.http2.max_pings_without_data", 0),   
        ("grpc.http2.min_time_between_pings_ms", 5000),  
        ("grpc.http2.min_ping_interval_without_data_ms", 5000) 
    ]

    channel = grpc.insecure_channel("localhost:50051", options=options)
    return chat_pb2_grpc.ChatServiceStub(channel)

def authenticate(stub):
    """Handles login and registration via gRPC."""
    while True:
        username = input("👤 Enter your username: ").strip()
        response = stub.CheckUserExists(chat_pb2.UsernameRequest(username=username))

        if response.exists:
            print("🔹 Username found. Proceeding to login...")
            while True:
                password = input("🔑 Enter your password: ").strip()
                login_response = stub.LoginUser(chat_pb2.LoginRequest(username=username, password=password))

                if login_response.status == "OK":
                    print(f"\n🎉 Welcome, {username}!")
                    return stub, username
                else:
                    print("❌ Invalid password. Try again.")
        else:
            print("🔹 Username NOT found. Registering a new account...")
            while True:
                new_username = input("👤 Enter a unique username: ").strip()
                password = input("🔑 Enter your password: ").strip()
                register_response = stub.RegisterUser(chat_pb2.RegisterRequest(username=new_username, password=password))

                if register_response.status == "OK":
                    print(f"🎉 New account created for {new_username}! Please log in.")
                    return stub, new_username
                else:
                    print("❌ Username already taken. Try another.")

def get_messages(stub, username):
    """Fetches and displays messages."""
    response = stub.GetMessages(chat_pb2.UsernameRequest(username=username))
    messages = response.messages

    if messages:
        print(f"\n📩 Messages for {username}:")
        for idx, message in enumerate(messages):
            print(f"{idx+1}. {message}")
        return messages
    else:
        print("📮 No messages found.")
        return []

def send_message(stub, username):
    """Handles sending a message."""
    users_response = stub.ListUsers(chat_pb2.EmptyRequest())
    users = users_response.users
    print("\n👥 Available users:")
    for user in users:
        print(f"👤 {user}")

    recipient = input("\n👥 Enter recipient username: ").strip()
    if recipient not in users:
        print("❌ User not found. Try again.")
        return

    message = input("🖌  Enter your message: ").strip()
    response = stub.SendMessage(chat_pb2.MessageRequest(sender=username, recipient=recipient, message=message))

def view_new_messages(stub, username):
    """Fetches and displays new messages."""
    # Fetch unread messages count
    unread_response = stub.GetUnreadMessages(chat_pb2.UsernameRequest(username=username))
    unread_count = len(unread_response.messages)
    if unread_count == 0:
        print("👀 No new messages.")
    print(f"📩 Fetching {unread_count} UNREAD message(s)...")
    for unread_message in unread_response.messages:
        print(f"📨 {unread_message}")
    response = stub.MarkMessagesRead(chat_pb2.UsernameRequest(username=username))

def delete_message(stub, username):
    """Handles deleting a message."""
    messages = get_messages(stub, username)
    if not messages:
        return

    delete_index = input("🔢 Enter the index of the message you want to delete: ").strip()
    if not delete_index.isdigit() or int(delete_index) not in range(1, len(messages) + 1):
        print("❌ Invalid index. Try again.")
        return

    response = stub.DeleteMessage(chat_pb2.DeleteMessageRequest(username=username, message_id=int(delete_index) - 1))

def delete_account(stub, username):
    """Handles deleting a user account."""
    confirm = input("🚨 Are you sure you want to delete your account? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("❌ Account deletion cancelled.")
        return

    response = stub.DeleteUser(chat_pb2.UsernameRequest(username=username))
    print(response.message)

def main():
    """Main chat client loop."""
    stub = connect_to_server()
    stub, username = authenticate(stub)

    while True:

        # Fetch unread messages count
        unread_response = stub.GetUnreadMessages(chat_pb2.UsernameRequest(username=username))
        unread_count = len(unread_response.messages)

        print(f"\n📮 You have {unread_count} unread message(s).")  
        
        print("\n🌐 Menu: \n1. 📤 Send a message \n2. 📨 View new messages \n3. 🗑  Delete a message \n4. 📒 Delete account \n5. 🚪 Logout")
        choice = input("\n📝 Enter your choice (1-5): ").strip()

        if choice == "1":
            send_message(stub, username)
        elif choice == "2":
            view_new_messages(stub, username)
        elif choice == "3":
            delete_message(stub, username)
        elif choice == "4":
            delete_account(stub, username)
            break
        elif choice == "5":
            print(f"🚪 Logging out {username}...")
            stub.LogoutUser(chat_pb2.UsernameRequest(username=username))
            break
        else:
            print("❌ Invalid choice. Try again.")

if __name__ == "__main__":
    main()