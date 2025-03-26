import os
import json

def append_to_log(log_path, cmd, payload):
    entry = {"cmd": cmd.decode() if isinstance(cmd, bytes) else cmd, "payload": payload}
    with open(log_path, "a") as f:
        f.write(json.dumps(entry) + "\n")

def replay_log(log_path):
    if not os.path.exists(log_path):
        return []
    entries = []
    with open(log_path, "r") as f:
        for line in f:
            entries.append(json.loads(line.strip()))
    return entries
