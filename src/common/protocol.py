"""
* File: protocol.py
* Author: Áron Vékássy, Karen Li

This file contains the wire protocol for the chat application.
"""

import struct
import hashlib

# Constants
LEN_UNAME = 32                               # Max username length
LEN_PASSWORD = 32                            # Max password length
LEN_MESSAGE = 256                            # Max message length
LEN_PASSHASH = hashlib.sha256().digest_size  # 32 bytes (SHA-256 hash)

# Request Codes (Sent by Client)
REQ_CHE = "CHECK___"   # Check if username exists
REQ_LOG = "LOGIN___"   # Login request
REQ_REG = "REGISTER"   # Register new user
REQ_BYE = "EXIT____"   # Close connection
REQ_SAV = "PERSIST_"   # Force server to save data
REQ_CPW = "CHANGEPW"   # Change password
REQ_SET = "SETPFILE"   # Set user profile file
REQ_GET = "GETPFILE"   # Get a user’s profile
REQ_UPA = "UPDATE__"   # Update user profile
REQ_ALL = "ALLUSERS"   # Get all registered users
REQ_DME = "DELEMESG"   # Delete a message
REQ_DEL = "DELEUSER"   # Delete a user

# Response Codes (Sent by Server)
RES_OK = "___OK___"                         # Success
RES_ERR_USER_EXISTS = "ERR_USER_EXISTS"     # Username already exists
RES_ERR_LOGIN = "ERR_LOGIN"                 # Invalid username or password
RES_ERR_REQ_FMT = "ERR_REQ_FMT"             # Bad request format
RES_ERR_NO_DATA = "ERR_NO_DATA"             # No data found
RES_ERR_NO_USER = "ERR_NO_USER"             # Requested user not found
RES_ERR_INV_CMD = "ERR_INVALID_COMMAND"     # Invalid command
RES_ERR_XMIT = "ERR_XMIT"                   # Transmission error 
RES_ERR_SERVER = "ERR_SERVER"               # Internal server error
RES_ERR_UNIMPLEMENTED = "ERR_UNIMPLEMENTED" # Feature not implemented

# Packet Structure (Fixed-Size Header + Payload)
HEADER_SIZE = 2  # Fixed header (magic bytes)
CMD_SIZE = 8     # Command length (padded)
PAYLOAD_SIZE = 4 # 4-byte integer indicating payload length
BUFFER_SIZE = 1024

# Compute SHA-256 hash
def hash_password_sha256(password): 
    return hashlib.sha256(password.encode()).hexdigest()

# Compute XOR checksum
def compute_checksum(payload):
    checksum = 0
    for byte in payload: checksum ^= byte
    return checksum.to_bytes(1, 'big')

# Create a structured request packet
def create_packet(command, payload): 
    # Format: [Header (2B)] + [Command (8B)] + [Payload Length (4B)] + [Payload (Var)] + [Checksum (1B)]
    if isinstance(command, str):
        command = command.encode()

    payload_bytes = payload.encode()
    payload_len = len(payload_bytes)

    # Pack as big-endian 4-byte integer
    payload_length_bytes = struct.pack("!I", payload_len)
    packet = (
        b'\xAA\xBB' +                       # Magic header
        command.ljust(CMD_SIZE, b'\x00') +  # Command (8 bytes, padded)
        payload_length_bytes +              # Payload length (4 bytes, big-endian)
        payload_bytes +                     # Payload (variable length)
        compute_checksum(payload_bytes)     # Checksum (1 byte)
    )
    return packet

# Parse a received packet
def parse_packet(packet):
    if len(packet) < HEADER_SIZE + CMD_SIZE + PAYLOAD_SIZE + 1:
        print(f"❌ Packet too short: Expected at least {HEADER_SIZE + CMD_SIZE + PAYLOAD_SIZE + 1} bytes, got {len(packet)}")
        return None, None, "Invalid packet length"

    header = packet[:HEADER_SIZE]
    if header != b'\xAA\xBB':
        print("❌ Invalid header detected.")
        return None, None, "Invalid header"

    # Extract and clean up command
    command = packet[HEADER_SIZE:HEADER_SIZE + CMD_SIZE].rstrip(b'\x00')  # Remove padding

    try:
        payload_len = struct.unpack("!I", packet[HEADER_SIZE + CMD_SIZE:HEADER_SIZE + CMD_SIZE + PAYLOAD_SIZE])[0]
    except struct.error:
        print("❌ Failed to unpack payload length.")
        return None, None, "Invalid payload length"

    # print(f"🛠  Parsed Command: {command}, Payload Length: {payload_len}")  # Debugging print

    if len(packet) < HEADER_SIZE + CMD_SIZE + PAYLOAD_SIZE + payload_len + 1:
        print(f"❌ Truncated packet: Expected {HEADER_SIZE + CMD_SIZE + PAYLOAD_SIZE + payload_len + 1}, got {len(packet)}")
        return None, None, "Truncated packet"

    payload = packet[HEADER_SIZE + CMD_SIZE + PAYLOAD_SIZE:HEADER_SIZE + CMD_SIZE + PAYLOAD_SIZE + payload_len]
    checksum = packet[HEADER_SIZE + CMD_SIZE + PAYLOAD_SIZE + payload_len]

    # Verify checksum
    if checksum != compute_checksum(payload)[0]:
        print("❌ Checksum mismatch.")
        return None, None, "Checksum mismatch"

    return command.decode(), payload.decode(), RES_OK

# Validate the length of a string
def validate_length(input_str, max_length, field_name):
    if not input_str:
        print(f"❌ {field_name} cannot be empty.")
        return False
    if len(input_str) > max_length:
        print(f"❌ {field_name} exceeds maximum length of {max_length} characters.")
        return False
    return True

# Verify a hashed password
def verify_password(stored_password, entered_password): 
    return stored_password == hash_password_sha256(entered_password)