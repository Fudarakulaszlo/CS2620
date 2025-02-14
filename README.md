# Homework 1 - CS2620

## Project Directory Structure

```
src/
  ├── client/
  │       ├── client.py
  │       └── request.py
  ├── server/
  │       ├── server.py
  │       └── response.py
  ├── common/
  │       ├── protocols.py
  │       └── json_protocol.py
  │       └── messages/
  └── GUI/ 
        └── gui.py



```

## Flags to set

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

## Testing the Code
To test the code, be sure to be in the right directory:
```
cd CS2620/src
```
To run the server, you can run the following commands in your terminal:
```
python server/server.py -p 9999
```
In a separate terminal, you can run the following commands to test the client:
```
python client/client.py
```