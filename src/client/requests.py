"""
* File: requests.py
* Author: Áron Vékássy, Karen Li

This file contains the client request code for the chat application.
"""

import sys
import os
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.protocol import *
from common.json_protocol import *

# Send a structured request to the server and receive a response
def send_request(client_socket, command, payload=""): 
    if CHE_TIME: start_time = time.time()
    if USE_JSON:
        if isinstance(command, bytes): command = command.decode() 
        request_str = create_json(command, payload)
        client_socket.sendall(request_str.encode())
        response = client_socket.recv(BUFFER_SIZE).decode() 
        parsed_response = parse_json(response)
    else:
        packet = create_packet(command, payload)
        client_socket.sendall(packet)
        response = client_socket.recv(BUFFER_SIZE) 
        parsed_response = parse_packet(response)
    if CHE_TIME: 
        end_time = time.time()
        print(f"\n📏 Request Size: {len(request_str.encode() if USE_JSON else packet)} bytes")
        print(f"📏 Response Size: {len(response)} bytes")
        print(f"⏳ Round-trip time: {end_time - start_time:.6f} sec \n")
    return parsed_response

# Request to check if a username exists
def request_check_user_exists(client_socket, username): 
    response_cmd, response_payload, status = send_request(client_socket, REQ_CHE, username)
    return response_cmd, response_payload, status

# Request to register a new user
def request_register(client_socket, username, password): 
    hashed_password = hash_password_sha256(password)
    response_cmd, response_payload, status = send_request(client_socket, REQ_REG, f"{username}|{hashed_password}")
    return response_cmd, response_payload, status

# Request to log in
def request_login(client_socket, username, password): 
    hashed_password = hash_password_sha256(password)
    response_cmd, response_payload, status = send_request(client_socket, REQ_LOG, f"{username}|{hashed_password}")
    return response_cmd, response_payload, status

# Request to send receiev a message
def request_set_profile(client_socket, username, message, target_user): 
    response_cmd, response_payload, status = send_request(client_socket, REQ_SET, f"{username}|{message}|{target_user}")
    return response_cmd, response_payload, status

# Request to mark a message as read
def request_update_profile(client_socket, username):
    response_cmd, response_payload, status = send_request(client_socket, REQ_UPA, username)
    return response_cmd, response_payload, status

# Request to get a user's message data
def request_get_profile(client_socket, username): 
    response_cmd, response_payload, status = send_request(client_socket, REQ_GET, username)
    return response_cmd, response_payload, status

# Request to delete a message
def request_delete_messages(client_socket, username, message_id):
    response_cmd, response_payload, status = send_request(client_socket, REQ_DME, f"{username}|{message_id}")
    return response_cmd, response_payload, status

# Request to list all users
def request_list_users(client_socket, username): 
    response_cmd, response_payload, status = send_request(client_socket, REQ_ALL, username)
    return response_cmd, response_payload, status

# Request to save the user database
def request_save_users(client_socket, username): 
    response_cmd, response_payload, status = send_request(client_socket, REQ_SAV, username)  
    return response_cmd, response_payload, status

def request_delete_profile(client_socket, username):
    response_cmd, response_payload, status = send_request(client_socket, REQ_DEL, username)
    return response_cmd, response_payload, status

# Request to log out
def request_logout(client_socket, username): 
    response_cmd, response_payload, status = send_request(client_socket, REQ_BYE, username)
    return response_cmd, response_payload, status
