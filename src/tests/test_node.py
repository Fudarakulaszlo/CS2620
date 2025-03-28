import unittest
import sys
import os
import json
import tempfile
import threading
import time

# Adjust path to import from project root.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from server.node import (
    initiate_election,
    update_local_membership,
    write_local_membership_file,
    load_local_membership_or_fallback,
    NODE_ID,
    MEMBERSHIP,
    LOCAL_MEMBERSHIP_FILE
)
from common.protocol import hash_password_sha256

class TestNodeFunctions(unittest.TestCase):

    def setUp(self):
        # Create a temporary directory to simulate the environment.
        self.temp_dir = tempfile.mkdtemp()
        # Create a dummy initial membership file.
        self.initial_membership = [
            {"id": 1, "host": "127.0.0.1", "port": 9001},
            {"id": 2, "host": "127.0.0.1", "port": 9002}
        ]
        self.initial_membership_path = os.path.join(self.temp_dir, "membership.json")
        with open(self.initial_membership_path, "w") as f:
            json.dump(self.initial_membership, f)
        # Override LOCAL_MEMBERSHIP_FILE to point inside temp_dir
        global LOCAL_MEMBERSHIP_FILE
        LOCAL_MEMBERSHIP_FILE = os.path.join(self.temp_dir, "membership_node_test.json")
        # Initialize MEMBERSHIP by loading the fallback file.
        from server.node import load_local_membership_or_fallback
        self.membership_loaded = load_local_membership_or_fallback(self.initial_membership_path)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_load_local_membership_or_fallback(self):
        # Check that the membership loaded is equal to our initial membership.
        self.assertEqual(self.membership_loaded, self.initial_membership)
        # Now check that the local membership file was written.
        self.assertTrue(os.path.exists(LOCAL_MEMBERSHIP_FILE))
        with open(LOCAL_MEMBERSHIP_FILE, "r") as f:
            data = json.load(f)
        self.assertEqual(data, self.initial_membership)

    def test_update_local_membership(self):
        # Test updating membership.
        new_membership = [
            {"id": 1, "host": "127.0.0.1", "port": 9001},
            {"id": 2, "host": "127.0.0.1", "port": 9002},
            {"id": 3, "host": "127.0.0.1", "port": 9003}
        ]
        update_local_membership(new_membership)
        self.assertEqual(MEMBERSHIP, new_membership)
        with open(LOCAL_MEMBERSHIP_FILE, "r") as f:
            data = json.load(f)
        self.assertEqual(data, new_membership)

    def test_initiate_election_no_higher_nodes(self):
        # This is a placeholder test: if there's no node with a higher ID,
        # initiate_election() should set this node as leader.
        # We set MEMBERSHIP such that this node has the highest id.
        global NODE_ID
        NODE_ID_backup = NODE_ID
        NODE_ID = 10  # assume current node id is 10
        from server.node import NODE_ROLE, LEADER_INFO
        MEMBERSHIP.clear()
        MEMBERSHIP.extend([
            {"id": 5, "host": "127.0.0.1", "port": 9001},
            {"id": 10, "host": "127.0.0.1", "port": 9002}
        ])
        initiate_election()
        # After election, since current node is highest, it should become leader.
        self.assertEqual(NODE_ROLE, "LEADER")
        self.assertIsNotNone(LEADER_INFO)
        NODE_ID = NODE_ID_backup

if __name__ == '__main__':
    unittest.main()
