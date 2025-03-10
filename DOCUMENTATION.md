# Wire Protocol Documentation for the Chat Application

## Overview

This document provides an overview of the wire protocol used in the chat application. It defines the structure of communication between the client and the server, including request and response codes, message formats, and validation mechanisms.

## Request Codes (Client-Sent Commands)

```
| Code        | Description                     |
|-------------|---------------------------------|
| CHECK___    | Check if a username exists.     |
| LOGIN___    | User login request.             |
| REGISTER    | Register a new user.            |
| EXIT____    | Close the connection.           |
| PERSIST_    | Force server to save data.      |
| SETPFILE    | Upload user profile file.       |
| GETPFILE    | Retrieve user profile file.     |
| UPDATE__    | Update user profile.            |
| ALLUSERS    | Retrieve all registered users.  |
| REQ_DME     | Delete a message                |
| REQ_DEL     | Delete a user                   |
```

## Request Codes (Client-Sent Commands)

```
 Code                  | Description                       |
|----------------------|-----------------------------------|
| ___OK___             | Request was successful.           |
| ERR_USER_EXISTS      | Username already exists.          |
| ERR_LOGIN            | Invalid username or password.     |
| ERR_REQ_FMT          | Incorrect request format.         |
| ERR_NO_DATA          | No data available.                |
| ERR_NO_USER          | User not found.                   |
| ERR_INVALID_COMMAND  | Command not recognized.           |
| ERR_XMIT             | Transmission error.               |
| ERR_CRYPTO           | Decryption error.                 |
| ERR_SERVER           | Internal server error.            |
| ERR_UNIMPLEMENTED    | Feature not implemented.          |
```


## Packet Structure

```
+------------+------------+----------------+------------+-----------+
|  Header    |  Command   | Payload Length |  Payload   | Checksum  |
|   (2B)     |   (8B)     |      (4B)      |  (Varies)  |   (1B)    |
+------------+------------+----------------+------------+-----------+
```