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
  │       └── messages/
  └── GUI/ 
        └── gui.py



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