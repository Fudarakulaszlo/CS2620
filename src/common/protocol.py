"""
* File: protocol.py
* Author: Áron Vékássy, Karen Li

This file contains the wire protocol for the chat application.
"""

import struct
import hashlib

# JSON mode flag
USE_JSON = False

# TIME flag
CHE_TIME = True

# Constants
LEN_UNAME = 32                               # Max username length
LEN_PASSWORD = 32                            # Max password length
LEN_MESSAGE = 256                            # Max message length
LEN_PASSHASH = hashlib.sha256().digest_size  # 32 bytes (SHA-256 hash)

# Request Codes (Sent by Client)
REQ_CHE = b"CHECK___"   # Check if username exists
REQ_LOG = b"LOGIN___"   # Login request
REQ_REG = b"REGISTER"   # Register new user
REQ_BYE = b"EXIT____"   # Close connection
REQ_SAV = b"PERSIST_"   # Force server to save data
REQ_CPW = b"CHANGEPW"   # Change password
REQ_SET = b"SETPFILE"   # Set user profile file
REQ_GET = b"GETPFILE"   # Get a user’s profile
REQ_UPA = b"UPDATE__"   # Update user profile
REQ_ALL = b"ALLUSERS"   # Get all registered users
REQ_DME = b"DELEMESG"   # Delete a message
REQ_DEL = b"DELEUSER"   # Delete a user
REQ_JOI = b"JOINFOLL"   # (Old join command, not used in new design)

# New Request/Response Codes for election, heartbeat, and joining
REQ_ELEC    = b"ELECT___"   # Election initiation
RES_OK_ELEC = b"ELEC_OK_"   # Response to election initiation
REQ_COORD   = b"COORD___"   # New leader announcement
REQ_HRTBT   = b"HEARTBT_"   # Heartbeat message
REQ_JOIN    = b"JOINNODE"   # New node join request
RES_JOIN    = b"JOIN_OK_"   # Response to join request with assigned id and membership

# Response Codes (Sent by Server)
RES_OK = b"___OK___"                        # Success
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
    for byte in payload:
        checksum ^= byte
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
    # Extract command and payload from packet.
    command = packet[0 + HEADER_SIZE:HEADER_SIZE + CMD_SIZE].rstrip(b'\x00')
    try:
        payload_len = struct.unpack("!I", packet[HEADER_SIZE + CMD_SIZE:HEADER_SIZE + CMD_SIZE + PAYLOAD_SIZE])[0]
    except struct.error:
        return None, None, "Invalid payload length"
    payload = packet[HEADER_SIZE + CMD_SIZE + PAYLOAD_SIZE:HEADER_SIZE + CMD_SIZE + PAYLOAD_SIZE + payload_len]
    return command, payload.decode(), RES_OK

def validate_length(input_str, max_length, field_name):
    if not input_str:
        print(f"❌ {field_name} cannot be empty.")
        return False
    if len(input_str) > max_length:
        print(f"❌ {field_name} exceeds maximum length of {max_length} characters.")
        return False
    return True

def verify_password(stored_password, entered_password): 
    return stored_password == hash_password_sha256(entered_password)
