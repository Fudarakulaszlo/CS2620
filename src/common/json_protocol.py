"""
json_protocol.py

Handles JSON-based request and response formatting for the chat application.
"""

import json

# Create a structured JSON request
def create_json(command, payload=""): 
    if isinstance(command, bytes): command = command.decode() 
    request = {
        "command": command,
        "payload": payload
    }
    return json.dumps(request)

# Parse a JSON response
def parse_json(response): 
    try:
        data = json.loads(response)
        return data.get("command", None), data.get("payload", ""), "OK"
    except json.JSONDecodeError:
        return None, None, "Invalid JSON format"