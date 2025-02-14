"""
* File: client.py
* Author: Áron Vékássy, Karen Li

This file contains the client code for the chat application.
"""

import socket
import sys
import os
import getpass

# Add the parent directory to the module search path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.protocol import *
from requests import *

# Server Configuration
HOST = "localhost"
PORT = 9999  # Must match the server port

# Connect to the chat server
def connect_to_server(): 
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((HOST, PORT))
        print(f"✅ Connected to server at {HOST}:{PORT}")
        return client_socket
    except ConnectionRefusedError:
        print(f"❌ Connection failed! Is the server running on {HOST}:{PORT}?")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

# Authenticate user (login/register)
def authenticate(client_socket): 
    while True:
        # Prompt for username and check if username entered is valid
        username = input("👤 Enter your username: ").strip()
        if not validate_length(username, LEN_UNAME, "Username"): continue
        # Check if username exists
        user_exists_response = request_check_user_exists(client_socket, username) 
        # Username exists
        if user_exists_response[0] == RES_OK or user_exists_response[0] == '___OK___': 
            print("🔹 Username found. Proceeding to login...")
            while True:
                # Prompt for password and check if password entered is valid
                password = input("🔑 Enter your password: ").strip()
                if not validate_length(password, LEN_PASSWORD, "Password"): continue
                # Request login
                login_response = request_login(client_socket, username, password)
                # Login successful 
                if login_response[0] == RES_OK or user_exists_response[0] == '___OK___':
                    print(f"🎉 Welcome, {username}!")
                    return username, password
                # Login failed
                else:
                    print("❌ Invalid password. Try again.")
        # Username does not exist and user wants to register
        else:
            print("🔹 Username NOT found. Registering a new account...")
            while True:
                # Prompt for username and check if username entered is valid
                new_username = input("👤 Enter a unique username: ").strip()
                if not validate_length(new_username, LEN_UNAME, "Username"): continue 
                # Prompt for password and check if password entered is valid
                password = input("🔑 Enter your password: ").strip()
                if not validate_length(password, LEN_PASSWORD, "Password"): continue
                # Request registration
                register_response = request_register(client_socket, new_username, password)
                # Registration successful
                if register_response[0] == RES_OK or register_response[0] == '___OK___':
                    # Request to save user data
                    save_response = request_save_users(client_socket, new_username)
                    if save_response[0] == RES_OK or save_response[0] == '___OK___':
                        print(f"🎉 New account created for {new_username}! Please log in.")
                        username = new_username  # Set new username for login
                        break  # Proceed to login
                    else:
                        print("❌ Error saving user data. Please try again.")
                # Registration failed
                else:
                    print("❌ Username already taken. Try another.")

if __name__ == "__main__":
    # Connect to server
    client_socket = connect_to_server()

    # Authenticate user (login or register)
    username, password = authenticate(client_socket)

    # Main loop
    while True:
        # Request user profile containing messages
        get_profile_response = request_get_profile(client_socket, username)
        formatted_messages, unread_messages = [], []
        # If there are messages
        if get_profile_response[1] != "":
            messages = get_profile_response[1].strip().split('\n')
            for message in messages:
                status, content, sender = message.split(',')
                formatted_message = f"[{status.capitalize()}] {sender}: {content}"
                formatted_messages.append(formatted_message)
                if status.upper() == "UNREAD": unread_messages.append(formatted_message)
            print(f"📮 Unread messages count: {len(unread_messages)}")
        # No messages
        else:
            print(f"📮 You have no unread messages!")

        # Display menu
        print("\n🌐 Menu: \n1. 📤 Send a message \n2. 📨 View messages \n3. 🗑  Delete a message \n4. 📒 Delete account \n5. 🚪 Logout")
        # Get user choice and check if choice entered is valid
        choice = input("\n📝 Enter your choice (1, 2, 3, 4, 5): ")
        if choice not in ["1", "2", "3", "4", "5"]:
            print("❌ Invalid choice. Please try again.")
            continue

        # Process user choice
        # Logout and request to disconnect
        if choice == "5": request_logout(client_socket, username)
        else:
            # Send a message
            if choice == "1":  
                # Request list of all users and display
                get_users_response = request_list_users(client_socket, username)
                users = get_users_response[1].strip().split('\n')
                print("👥 Available users:")
                for u in users: print(f"👤 {u}")
                # Get recipient's username and check if username entered is valid
                target_user  = input("\n👥 Enter the recipient's username: ").strip()
                if not validate_length(target_user, LEN_UNAME, "Username"): continue
                # Check if username exists
                user_exists_response = request_check_user_exists(client_socket, target_user)
                # Username does not exist
                while user_exists_response[0] != RES_OK and user_exists_response[0] != '___OK___':
                    print("❌ User not found. Try again.")
                    target_user = input("👥 Enter the recipient's username: ").strip()
                    if not validate_length(target_user, LEN_UNAME, "Username"): continue
                    user_exists_response = request_check_user_exists(client_socket, target_user)
                # Username exists
                request_get_profile(client_socket, target_user)
                # Get message and check if message entered is valid
                message = input("🖌  Enter your message: ").strip()
                if not validate_length(message, LEN_MESSAGE, "Username"): continue
                # Record the message on both the sender and recipient
                request_set_profile(client_socket, username, message, target_user)
                print("📬 Message sent!")
                continue
            # View messages
            elif choice == "2":  
                # If there are NO unread messages then skip
                if len(unread_messages) == 0: continue
                # Display unread messages
                for unread in unread_messages: print(f"💬 {unread}")
                # Request to update message status
                request_update_profile(client_socket, username)
                print("📭 All messages viewed!")
                continue
            # Delete a message
            elif choice == "3":  
                # If there are NO messages then skip
                if len(formatted_messages) == 0:
                    print("❌ You have no messages to delete.")
                    continue
                # Display all messages
                print("\n💬 Your messages:")
                for i, message in enumerate(formatted_messages):
                    if message.startswith("[Unread]"): print(f"🔴 {i+1}. {message}")
                    elif message.startswith("[Read]"): print(f"🟢 {i+1}. {message}")
                    else: print(f"🔵 {i+1}. {message}")
                # Get message index and check if index entered is valid
                delete_message = input("🔢 Enter the index of the message you want to delete: ").strip() 
                if not delete_message.isdigit(): print("❌ Invalid index. Please enter a valid number.")
                else:
                    delete_index = int(delete_message)  # Convert to integer
                    # Check if the index is within the valid range
                    if 1 <= delete_index <= len(formatted_messages):
                        # Request to delete message
                        request_delete_messages(client_socket, username, delete_index-1)
                        print("🗑  Message deleted!")
                    else: print("❌ Invalid index. Please enter a number within the valid range.")
                continue
            # Delete account and exit the program
            else: 
                request_delete_profile(client_socket, username)
                print("🚮 Account deleted. Exiting...")
                request_logout(client_socket, username)
        break
