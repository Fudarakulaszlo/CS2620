# Homework 4 - CS2620

## Project Directory Structure

```
src/
  ├── client/
  │       ├── client.py
  │       └── request.py
  ├── server/
  │       ├── leader.py
  │       ├── follower.py
  │       ├── log_util.py
  │       ├── responses.py
  │       └── config.json
  └── common/
          ├── protocols.py
          ├── json_protocol.py
          ├── logs/
          │     ├── follower.log
          │     └── leader.log
          ├── messages/
          │     ├── <USERNAME>.dat
          │     └── ...
          └── user.dat
```

## System Architecture
```
[Client] <--> [Leader Server] <---> [Follower 1]
                              <---> [Follower 2]
                              <---> [Follower 3]
```

## Configuration File (server/config.json)
Edit this file to change replica addresses or add a real LAN IP.
```
{
  "port": 9999,
  "log": "common/logs/leader.log",
  "replicas": [
    { "host": "127.0.0.1", "port": 9991 },
    { "host": "127.0.0.1", "port": 9992 },
    { "host": "127.0.0.1", "port": 9993 }
  ]
}
```

## Testing the Code
To test the code, be sure to be in the right directory for ALL terminals:
```
cd CS2620/src
```
### Step 1: Start Follower Servers

Open 3 terminals:
```
python3 server/follower.py 9991
```
```
python3 server/follower.py 9992
```
```
python3 server/follower.py 9993
```

### Step 2: Start the Leader Server
In a new terminal
```
python3 server/leader.py --config server/config.json
```

### Step 3: Start the Client
In another new terminal
```
python3 client/client.py
```

### Check Local Logs
```
tail -f common/logs/leader.log
```