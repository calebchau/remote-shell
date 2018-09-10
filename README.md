# RemoteShell

Sets up a multi-process telnet-like client and server. When the client connects
to the server, the server forks a process to run a bash shell and relays the
output from the shell from commands sent by the client. All communication is
encrypted using the libmcrypt data encryption library.

## Usage
Make sure to build the executables by running the Makefile like so:
```
make
```
### Start server
```
./lab1b-server --port=port# --encrypt=keyfile
```
### Start client
```
./lab1b-client --port=port# --log=filename --host=hostname --encrypt=keyfile
```

## Options
### Server
#### --port
Sets the port number that the server will listen on.
#### --encrypt
Sets the file that the key used for encryption and decryption is in.
### Client
#### --port
Sets the port number that the client will try to connect to on the server.
#### --log
Sets the file that the client will use to log its communication with the server
which should all be encrypted.
#### --host
Sets the host that the client will try to connect to, e.g. localhost or IP of
the server.
#### --encrypt
Sets the file that the key used for encryption and decryption is in.
