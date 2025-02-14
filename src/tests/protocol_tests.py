"""
* File: protocol_tests.py
* Author: Áron Vékássy, Karen Li
*
* This file contains the unit tests for the wire protocol code.
"""

import unittest
import sys
import os
import struct
import hashlib

# Import the module under test.
# Adjust the path so that the "common" package can be found.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import common.protocol as protocol

class TestProtocol(unittest.TestCase):

    def test_hash_password_sha256(self):
        password = "secret"
        expected = hashlib.sha256(password.encode()).hexdigest()
        self.assertEqual(protocol.hash_password_sha256(password), expected)

    def test_compute_checksum(self):
        payload = b"abc"
        # Compute expected checksum:
        # 0 ^ 97 = 97, 97 ^ 98 = 3, 3 ^ 99 = 96
        expected = (96).to_bytes(1, 'big')
        self.assertEqual(protocol.compute_checksum(payload), expected)

    def test_create_packet(self):
        command = "CMDTEST"
        payload = "hello"
        packet = protocol.create_packet(command, payload)

        expected_command = command.encode().ljust(protocol.CMD_SIZE, b'\x00')
        payload_bytes = payload.encode()
        payload_length_bytes = struct.pack("!I", len(payload_bytes))
        checksum = protocol.compute_checksum(payload_bytes)
        expected_packet = b'\xAA\xBB' + expected_command + payload_length_bytes + payload_bytes + checksum
        self.assertEqual(packet, expected_packet)

    def test_parse_packet_valid(self):
        command = "CMDTEST"
        payload = "hello"
        packet = protocol.create_packet(command, payload)
        parsed_command, parsed_payload, status = protocol.parse_packet(packet)
        self.assertEqual(parsed_command, command.encode())
        self.assertEqual(parsed_payload, payload)
        self.assertEqual(status, protocol.RES_OK)

    def test_parse_packet_too_short(self):
        packet = b'\xAA\xBB'
        parsed_command, parsed_payload, status = protocol.parse_packet(packet)
        self.assertIsNone(parsed_command)
        self.assertIsNone(parsed_payload)
        self.assertEqual(status, "Invalid packet length")

    def test_parse_packet_invalid_header(self):
        command = "CMDTEST"
        payload = "hello"
        packet = protocol.create_packet(command, payload)
        # Corrupt the header.
        packet = b'\x00\x00' + packet[2:]
        parsed_command, parsed_payload, status = protocol.parse_packet(packet)
        self.assertIsNone(parsed_command)
        self.assertIsNone(parsed_payload)
        self.assertEqual(status, "Invalid header")

    def test_parse_packet_truncated(self):
        command = "CMDTEST"
        payload = "hello"
        packet = protocol.create_packet(command, payload)
        # Truncate the packet to simulate missing data.
        truncated_packet = packet[:-2]
        parsed_command, parsed_payload, status = protocol.parse_packet(truncated_packet)
        self.assertIsNone(parsed_command)
        self.assertIsNone(parsed_payload)
        self.assertEqual(status, "Truncated packet")

    def test_parse_packet_checksum_mismatch(self):
        command = "CMDTEST"
        payload = "hello"
        packet = bytearray(protocol.create_packet(command, payload))
        # Modify one byte in the payload to cause a checksum error.
        header_len = protocol.HEADER_SIZE
        cmd_len = protocol.CMD_SIZE
        payload_len_field = protocol.PAYLOAD_SIZE
        start_payload = header_len + cmd_len + payload_len_field
        packet[start_payload] ^= 0xFF  # Flip bits
        packet = bytes(packet)
        parsed_command, parsed_payload, status = protocol.parse_packet(packet)
        self.assertIsNone(parsed_command)
        self.assertIsNone(parsed_payload)
        self.assertEqual(status, "Checksum mismatch")

    def test_validate_length_valid(self):
        self.assertTrue(protocol.validate_length("hello", 10, "Test Field"))

    def test_validate_length_empty(self):
        self.assertFalse(protocol.validate_length("", 10, "Test Field"))

    def test_validate_length_exceeds(self):
        self.assertFalse(protocol.validate_length("hello world", 5, "Test Field"))

    def test_verify_password_success(self):
        password = "secret"
        stored = protocol.hash_password_sha256(password)
        self.assertTrue(protocol.verify_password(stored, password))

    def test_verify_password_failure(self):
        password = "secret"
        stored = protocol.hash_password_sha256("notsecret")
        self.assertFalse(protocol.verify_password(stored, password))

if __name__ == '__main__':
    unittest.main()
