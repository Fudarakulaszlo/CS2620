"""
* File: protocol.py
* Author: Áron Vékássy, Karen Li

This file contains the wire protocol for the chat application.
"""

import struct
import hashlib

# Constants
LEN_UNAME = 64                               # Max username length
LEN_PASSWORD = 64                            # Max password length
LEN_PASSHASH = hashlib.sha256().digest_size  # 32 bytes (SHA-256 hash)
LEN_PROFILE_FILE = 1048576                   # 1MB max profile size

# Command IDs (1 Byte Each)
REQ_LOG = b"LOGIN___"   # Login request
REQ_REG = b"REGISTER"   # Register new user
REQ_BYE = b"EXIT____"   # Close connection
REQ_SAV = b"PERSIST_"   # Force server to save data
REQ_CPW = b"CHANGEPW"   # Change password
REQ_SET = b"SETPFILE"   # Set user profile file
REQ_GET = b"GETPFILE"   # Get a user’s profile
REQ_ALL = b"ALLUSERS"   # Get all registered users


# Response Codes (Sent by Server)
RES_OK = b"___OK___"                         # Success
RES_ERR_USER_EXISTS = b"ERR_USER_EXISTS"     # Username already exists
RES_ERR_LOGIN = b"ERR_LOGIN"                 # Invalid username or password
RES_ERR_REQ_FMT = b"ERR_REQ_FMT"             # Bad request format
RES_ERR_NO_DATA = b"ERR_NO_DATA"             # No data found
RES_ERR_NO_USER = b"ERR_NO_USER"             # Requested user not found
RES_ERR_INV_CMD = b"ERR_INVALID_COMMAND"     # Invalid command
RES_ERR_XMIT = b"ERR_XMIT"                   # Transmission error
RES_ERR_CRYPTO = b"ERR_CRYPTO"               # Decryption error
RES_ERR_SERVER = b"ERR_SERVER"               # Internal server error
RES_ERR_UNIMPLEMENTED = b"ERR_UNIMPLEMENTED" # Feature not implemented

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

    packet = (
        b'\xAA\xBB' +  # Magic header
        command.ljust(CMD_SIZE, b'\x00') +  # Command (padded to 8 bytes)
        struct.pack("!I", payload_len) +  # Payload length (4-byte integer)
        payload_bytes +  # Actual payload
        compute_checksum(payload_bytes)  # Checksum (1 byte)
    )
    return packet

# Parse a received packet
def parse_packet(packet): 
    print(f"📩 Received Raw Packet: {packet}")  # Debugging print

    if len(packet) < HEADER_SIZE + CMD_SIZE + PAYLOAD_SIZE + 1:
        print(f"❌ Packet too short: Expected at least {HEADER_SIZE + CMD_SIZE + PAYLOAD_SIZE + 1} bytes, got {len(packet)}")
        return None, None, "Invalid packet length"

    header = packet[:HEADER_SIZE]
    if header != b'\xAA\xBB':
        print("❌ Invalid header detected.")
        return None, None, "Invalid header"

    command = packet[HEADER_SIZE:HEADER_SIZE + CMD_SIZE].strip(b'\x00')

    try:
        payload_len = struct.unpack("!I", packet[HEADER_SIZE + CMD_SIZE:HEADER_SIZE + CMD_SIZE + PAYLOAD_SIZE])[0]
    except struct.error:
        print("❌ Failed to unpack payload length.")
        return None, None, "Invalid payload length"

    if len(packet) < HEADER_SIZE + CMD_SIZE + PAYLOAD_SIZE + payload_len + 1:
        print(f"❌ Truncated packet: Expected {HEADER_SIZE + CMD_SIZE + PAYLOAD_SIZE + payload_len + 1}, got {len(packet)}")
        return None, None, "Truncated packet"

    payload = packet[HEADER_SIZE + CMD_SIZE + PAYLOAD_SIZE:HEADER_SIZE + CMD_SIZE + PAYLOAD_SIZE + payload_len]
    checksum = packet[HEADER_SIZE + CMD_SIZE + PAYLOAD_SIZE + payload_len]

    if checksum != compute_checksum(payload)[0]:
        print("❌ Checksum mismatch.")
        return None, None, "Checksum mismatch"

    return command.decode(), payload.decode(), "OK"