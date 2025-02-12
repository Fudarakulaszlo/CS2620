"""
* File: requests.py
* Author: Áron Vékássy, Karen Li

This file contains the client request code for the chat application.
"""

import socket
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.protocol import *

# Send a structured request to the server and receive a response
def send_request(client_socket, command, payload=""): 
    packet = create_packet(command, payload)
    client_socket.sendall(packet)
    response = client_socket.recv(BUFFER_SIZE)
    return parse_packet(response)

# Request to register a new user
def request_register(client_socket, username, password): 
    hashed_password = hash_password_sha256(password)
    response_cmd, response_payload, status = send_request(client_socket, REQ_REG, f"{username}|{hashed_password}")
    return response_payload

# Request to log in
def request_login(client_socket, username, password): 
    hashed_password = hash_password_sha256(password)
    response_cmd, response_payload, status = send_request(client_socket, REQ_LOG, f"{username}|{hashed_password}")
    return response_payload

# Request to change password
def request_change_password(client_socket, username, old_password, new_password): 
    hashed_old_password = hash_password_sha256(old_password)
    hashed_new_password = hash_password_sha256(new_password)
    response_cmd, response_payload, status = send_request(client_socket, REQ_CPW, f"{username}|{hashed_old_password}|{hashed_new_password}")
    return response_payload

# Request to set user profile data
def request_set_profile(client_socket, username, password, profile_data): 
    hashed_password = hash_password_sha256(password)
    response_cmd, response_payload, status = send_request(client_socket, REQ_SET, f"{username}|{hashed_password}|{profile_data}")
    return response_payload

# Request to get a user's profile data
def request_get_profile(client_socket, username, password, target_username): 
    hashed_password = hash_password_sha256(password)
    response_cmd, response_payload, status = send_request(client_socket, REQ_GET, f"{username}|{hashed_password}|{target_username}")
    return response_payload

# Request to list all users
def request_list_users(client_socket, username, password): 
    hashed_password = hash_password_sha256(password)
    response_cmd, response_payload, status = send_request(client_socket, REQ_ALL, f"{username}|{hashed_password}")
    return response_payload

# Request to log out
def request_logout(client_socket, username): 
    response_cmd, response_payload, status = send_request(client_socket, REQ_BYE, username)
    return response_payload

# Request to save the user database
def request_save_users(client_socket, username, password): 
    hashed_password = hash_password_sha256(password)
    response_cmd, response_payload, status = send_request(client_socket, REQ_SAV, f"{username}|{hashed_password}")  
    return response_payload