'''
* File: server.py
* Author: Áron Vékássy, Karen Li

This file contains the server code for the chat application.
'''

import socket
import argparse
import sys

# Server Argument Structure 
class ServerArgs:
    # Stores command-line arguments for the server
    def __init__(self):
        self.port = 0  # Port number
        self.usage = False  # Help flag

# Print usage instructions.
def usage(progname):
    print(f"{progname}: The server half of a client-server chat application that allows users to send and receive text messages.")
    print("  -p [int]    Port number of the server")
    print("  -h          Print help (this message)")

# Parse command-line arguments and return a ServerArgs object
def parse_args():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-p", type=int, help="Port number")
    parser.add_argument("-h", action="store_true", help="Print help message")

    args = parser.parse_args()
    server_args = ServerArgs()

    if args.h: server_args.usage = True
    if args.p: server_args.port = args.p

    return server_args

# Create and bind a server socket
def create_server_socket(port):
    try:
        # Create a TCP socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind the socket to all available network interfaces
        server_socket.bind(("0.0.0.0", port))
        server_socket.listen(25)  # Maximum 5 pending connections

        print(f"Server listening on port {port}...")
        return server_socket

    except socket.error as e:
        sys.stderr.write(f"Error creating server socket: {e}\n")
        sys.exit(1)

# Receive data from a client and echo it back.
def echo_server(client_socket, client_address):
    print(f"Connected to {client_address}")
    try:
        while True:
            data = client_socket.recv(1024)  # Receive up to 1024 bytes
            if not data: break  
            print(f"Received from {client_address}: {data.decode()}")
            client_socket.sendall(data)  # Echo message back to client

    except socket.error as e:
        sys.stderr.write(f"Error in communication with {client_address}: {e}\n")

    finally:
        print(f"Closing connection to {client_address}")
        client_socket.close()

# Main function
def main():
    # Parse command-line arguments
    args = parse_args()
    if args.usage:
        usage(sys.argv[0])
        sys.exit(0)
    # Validate port number
    if args.port == 0:
        sys.stderr.write("Error: Port number must be specified using -p [port]\n")
        sys.exit(1)

    # Create and bind the server socket
    server_socket = create_server_socket(args.port)

    try:
        while True:
            print("Waiting for a client to connect...")
            client_socket, client_address = server_socket.accept()  # Accept a new client
            echo_server(client_socket, client_address)  # Handle client communication

    except KeyboardInterrupt:
        print("\nServer shutting down.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()
