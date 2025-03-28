# Homework 4 - CS2620

## Project Directory Structure

```
├─ src/
│  ├─ client/
│  │  ├─ requests.py        # Client-side request functions (send_request, etc.)
│  │  └─ ...
│  ├─ common/
│  │  ├─ protocol.py        # Defines wire protocol constants & packet structure
│  │  └─ ...
│  ├─ GUI/
│  │  ├─ gui.py             # Tkinter-based GUI client
│  │  └─ ...
│  └─ server/
│     ├─ node.py            # Main server node code (leader election, replication, membership)
│     ├─ join.py            # Script to request a new node join the cluster
│     ├─ log_util.py        # Tools for logging and replaying logs
│     └─ ...
         
```

## System Architecture
```
[Client] <---> [Server 1]
         <---> [Server 2]
         <---> [Server 3]
         <---> ...
```
## How to use

### Configuration File (server/membership.json)
Edit this file to change the initial replica addresses or add a real LAN IP.
```
[
  {"id": 1, "host": "127.0.0.1", "port": 9001},
  {"id": 2, "host": "127.0.0.1", "port": 9002},
  {"id": 3, "host": "127.0.0.1", "port": 9003}
]
```


### How to run the servers

1. Set up a `membership.json` with your initial cluster membership (or just an empty list if you plan to add all nodes dynamically). Make sure that 127.0.0.1 port 9001 is one of them (see GUI part why). Something like:

```
[
  {"id": 1, "host": "127.0.0.1", "port": 9001},
  {"id": 2, "host": "127.0.0.1", "port": 9002},
  {"id": 3, "host": "127.0.0.1", "port": 9003}
]
```
2. Go to the `src` folder. You should run all the code from there.

3. Start each node with a unique `--id`, `--host`, `--port`, and the same `--membership membership.json`:

```
python3 server/node.py --id 1 --host 127.0.0.1 --port 9001 --membership membership.json
python3 server/node.py --id 2 --host 127.0.0.1 --port 9002 --membership membership.json
python3 server/node.py --id 3 --host 127.0.0.1 --port 9003 --membership membership.json
```
- Each node creates a local `common/membership_node_{ID}.json`.
- They all begin as followers, wait for heartbeats or time out, then elect a leader automatically.


### Adding a New Node Dynamically

1. Use `join.py` to tell the current leader about a new node:

```
python3 server/join.py \
    --leader_host 127.0.0.1 --leader_port 9001 \
    --new_host 127.0.0.1   --new_port 9004
```
- The leader updates its membership list.
- The leader replicates the new membership to other existing nodes, so they also update their local membership files.

2. Start the new node:

```
python3 server/node.py --id 4 --host 127.0.0.1 --port 9004 --membership membership.json
```
- This node recognizes it’s a follower and does a post-startup pull from the leader to get the latest membership and data.

### Running the GUI Client

1. Launch the GUI:
```
python3 GUI/gui.py
```
- The GUI automatically tries to connect to the cluster.

- The client has a list of possibly running servers that it tries to join. Be default this is set to port 9001. While running, it fetches the latest server lists, so it can fail over to any of the running servers.

### Failover and Replication
- If you send a command that changes data (e.g., register user or send a message) to the leader, the leader replicates it to followers, appends to a local log, and returns success.
- Followers also periodically pull data from the leader if they missed updates.
- If the leader fails, a heartbeat timeout triggers a new election.
- A node with no heartbeats from the leader calls `initiate_election()`. Once it becomes leader, it starts sending heartbeats itself.

### Logging & Debugging
- Each node appends significant events to `common/logs/node_{ID}_events.log` (for major events) and a replication log to `common/logs/node_{ID}.log` for data changes.
- The GUI prints logs to the console (connection attempts, failover messages, etc.).