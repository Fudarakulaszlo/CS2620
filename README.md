# Homework 1 - CS2620

## Project Directory Structure

```
src/
  ├── client/
  │       ├── client.py
  │       ├── request.py
  │       └── client_rpc.py
  ├── server/
  │       ├── server.py
  │       ├── response.py
  │       └── server_rpc.py
  ├── common/
  │       ├── protocols.py
  │       ├── json_protocol.py
  │       ├── chat_pb2_grpc.py
  │       ├── chat_pb2.py
  │       ├── chat.proto
  │       ├── messages/
  │       ├── user.dat
  │       └── user.json
  ├── GUI/ 
  │       └── gui.py
  └── tests/
          ├── gui_tests.py
          ├── protocol_tests.py
          ├── request_tests.py
          ├── responses_tests.py
          ├── run_all_tests.py
          └── server_tests.py


```


## Testing the Code - FOR RPC (HW2) ONLY

To test the code, be sure to be in the right directory:
```
cd CS2620/src
```
To run the server, you can run the following commands in your terminal:
```
python server/server_rpc.py
```

In a separate terminal, you can run the following commands to test the client:
```
python client/client_rpc.py
```


## Flags to set - FOR WIRE PROTOCOL (HW1) ONLY

Set the flags in the file `common/protocols.py` to `True` to enable the JSON protocol or timer.

```
common/protocol.py

...

# JSON mode flag
USE_JSON = True

# TIME flag
CHE_TIME = True

...
```

## Testing the Code - FOR WIRE PROTOCOL (HW1) ONLY

To test the code, be sure to be in the right directory:
```
cd CS2620/src
```
To run the server, you can run the following commands in your terminal:
```
python server/server.py -p 9999
```

In a separate terminal, you can run the following commands to test the client with GUI:
```
python GUI/gui.py
```

OR test the client from a terminal:
```
python client/client.py
```

Additionally you can run the unit tests for the modules by running:
```
python tests/run_all_tests.py
```

After running it, when it seems to be stuck, put a keyboard interrupt to stop the server, we couldn't get around it for now, but the tests run properly.