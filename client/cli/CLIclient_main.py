# echo_client.py
import socket
import sys

HOST, PORT = input("enter hostname: "), 9999
data = input("enter data: ")
print('data =', data)

# create a TCP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # connect to server 
    sock.connect((HOST, PORT))

    # send data
    sock.sendall(bytes((data + "\n").encode()))

    # receive data back from the server
    received = str(sock.recv(1024))
finally:
    # shut down
    sock.close()

print("Sent     : {}".format(data))
print("Received : {}".format(received))
