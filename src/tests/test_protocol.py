import unittest
import struct
import hashlib
import json
from common.protocol import (
    create_packet,
    parse_packet,
    hash_password_sha256,
    compute_checksum,
    validate_length,
    verify_password,
    LEN_UNAME,
    LEN_PASSWORD,
    LEN_MESSAGE,
    RES_OK
)

class TestProtocolFunctions(unittest.TestCase):

    def test_create_and_parse_packet(self):
        command = b"TESTCMD"
        payload = "Hello, Chat!"
        packet = create_packet(command, payload)
        
        # Check that the packet starts with the magic header
        self.assertTrue(packet.startswith(b'\xAA\xBB'))
        
        # Parse the packet and check values
        parsed_cmd, parsed_payload, parsed_status = parse_packet(packet)
        # The command should be stripped of padding zeros
        self.assertEqual(parsed_cmd, command)
        self.assertEqual(parsed_payload, payload)
        self.assertEqual(parsed_status, RES_OK)

    def test_empty_payload(self):
        command = b"EMPTYCMD"
        payload = ""
        packet = create_packet(command, payload)
        parsed_cmd, parsed_payload, parsed_status = parse_packet(packet)
        self.assertEqual(parsed_payload, "")
        self.assertEqual(parsed_cmd, command)

    def test_long_payload(self):
        command = b"LONGCMD"
        payload = "A" * 200  # a payload with 200 characters
        packet = create_packet(command, payload)
        parsed_cmd, parsed_payload, parsed_status = parse_packet(packet)
        self.assertEqual(parsed_payload, payload)
        self.assertEqual(parsed_cmd, command)

    def test_compute_checksum(self):
        # Compute checksum for a known payload
        payload = b"ChecksumTest"
        checksum = compute_checksum(payload)
        # Manually compute XOR checksum for comparison
        expected = 0
        for byte in payload:
            expected ^= byte
        expected_checksum = expected.to_bytes(1, 'big')
        self.assertEqual(checksum, expected_checksum)

    def test_hash_password_sha256(self):
        password = "securepassword123"
        hashed = hash_password_sha256(password)
        expected = hashlib.sha256(password.encode()).hexdigest()
        self.assertEqual(hashed, expected)

    def test_verify_password(self):
        password = "mysecret"
        hashed = hash_password_sha256(password)
        self.assertTrue(verify_password(hashed, password))
        self.assertFalse(verify_password(hashed, "wrongpassword"))

    def test_validate_length_empty(self):
        # Should return False if input is empty
        self.assertFalse(validate_length("", LEN_UNAME, "Username"))
        
    def test_validate_length_exceeds(self):
        # Should return False if input exceeds maximum length
        long_input = "A" * (LEN_MESSAGE + 1)
        self.assertFalse(validate_length(long_input, LEN_MESSAGE, "Message"))
        
    def test_validate_length_valid(self):
        # Should return True for valid input length
        valid_input = "ValidUser"
        self.assertTrue(validate_length(valid_input, LEN_UNAME, "Username"))

if __name__ == '__main__':
    unittest.main()
