import socket
import protocol

flag = True

#  set the keys
PRIVET_KEY = 9283
PUBLIC_KEY = pow(protocol.G, PRIVET_KEY, protocol.P)
MAC_PRIVET_KEY = 7171
MAC_PUBLIC_KEY = 2731

#  server up
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("0.0.0.0", protocol.PORT))
server_socket.listen()
print("Server is up and running")

(client_socket, client_address) = server_socket.accept()
print("Client connected")

# send the public key
client_socket.sendall(str(PUBLIC_KEY).encode())
CLIENT_P_KEY = int(client_socket.recv(1024).decode())

client_socket.sendall(str(MAC_PUBLIC_KEY).encode())
CLIENT_MAC_KEY = int(client_socket.recv(1024).decode())

SHARED_SECRET = pow(CLIENT_P_KEY, PRIVET_KEY, protocol.P)
print('shared secret: ' + str(SHARED_SECRET))

while flag:
    signature, message = protocol.decrypt_message(client_socket, CLIENT_MAC_KEY, SHARED_SECRET)
    print(message)
    if message == 'EXIT':
        client_socket.close()
        flag = False
    elif signature:
        # the response is revers of the message
        revers = ''.join(reversed(message))
        encrypted_message = protocol.make_message(revers, SHARED_SECRET, MAC_PRIVET_KEY).encode()
        client_socket.sendall(encrypted_message)
    else:
        encrypted_message = protocol.make_message(message, SHARED_SECRET, MAC_PRIVET_KEY).encode()
        client_socket.sendall(encrypted_message)

print('EXIT server')
server_socket.close()
