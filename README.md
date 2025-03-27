# Homework 4 - CS2620

## Project Directory Structure

```
src/
  ├── client/
  │       ├── client.py
  │       └── request.py
  ├── server/
  │       ├── node.py
  │       ├── log_util.py
  │       ├── responses.py
  │       └── membership.json
  └── common/
          ├── protocols.py
          ├── json_protocol.py
          ├── logs/
          │     ├── nodeX.log
          │     └── ...
          ├── messages/
          │     ├── <USERNAME>.dat
          │     └── ...
          └── user.dat
```

## System Architecture
```
[Client] <---> [Server 1]
         <---> [Server 2]
         <---> [Server 3]
```

## Configuration File (server/config.json)
Edit this file to change replica addresses or add a real LAN IP.
```
[
  {"id": 1, "host": "127.0.0.1", "port": 9001},
  {"id": 2, "host": "127.0.0.1", "port": 9002},
  {"id": 3, "host": "127.0.0.1", "port": 9003}
]
```

## Testing the Code
To test the code, be sure to be in the right directory for ALL terminals:
```
cd CS2620/src
```
### Step 1: Start Servers

Open 3 terminals:
```
python3 server/node.py --id 3 --host 127.0.0.1 --port 9003 --membership server/membership.json
```
```
python3 server/node.py --id 2 --host 127.0.0.1 --port 9002 --membership server/membership.json
```
```
python3 server/node.py --id 1 --host 127.0.0.1 --port 9001 --membership server/membership.json
```

### Step 2: Start the Client
In another new terminal
```
python3 client/client.py
```

### Check Local Logs
```
tail -f common/logs/leader.log
```

### Add extra servers
```
python3 join.py --leader_host 127.0.0.1 --leader_port 9003 --new_host 127.0.0.1 --new_port 9004
```
Then start the new node with
```
python3 node.py --id 4 --host 127.0.0.1 --port 9004 --membership membership.json
```