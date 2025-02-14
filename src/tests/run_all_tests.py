#!/usr/bin/env python3
"""
File: run_all_tests.py
Author: Áron Vékássy, Karen Li

This script discovers and runs test files for the modules:
    protocol, requests, responses, server, and gui.
"""

import unittest
import sys
import os

def load_and_run(test_file, start_dir="tests"):
    print(f"\n{'='*20} Running {test_file} {'='*20}\n")
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=start_dir, pattern=test_file)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()

if __name__ == '__main__':
    # List the test file patterns to run, in desired order.
    test_files = [
        "protocol_tests.py",
        "requests_tests.py",
        "responses_tests.py",
        "server_tests.py",
        "gui_tests.py"
    ]
    
    # Adjust start_dir if your test files are located elsewhere.
    start_dir = "tests"  # Assuming all test files are inside a folder named "tests"

    all_success = True
    for test_file in test_files:
        success = load_and_run(test_file, start_dir=start_dir)
        if not success:
            all_success = False

    if all_success:
        print("\nAll tests passed successfully.")
        sys.exit(0)
    else:
        print("\nSome tests failed.")
        sys.exit(1)
