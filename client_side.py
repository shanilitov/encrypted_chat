import socket
import protocol

#  set the keys
PRIVET_KEY = 1546
PUBLIC_KEY = pow(protocol.G, PRIVET_KEY, protocol.P)

MAC_PRIVET_KEY = 11669
MAC_PUBLIC_KEY = 1229

#  connect to the server
my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
my_socket.connect(("127.0.0.1", protocol.PORT))

# send the public keys
my_socket.sendall(str(PUBLIC_KEY).encode())
SERVER_P_KEY = int(my_socket.recv(1024).decode())

my_socket.sendall(str(MAC_PUBLIC_KEY).encode())
SERVER_MAC_KEY = int(my_socket.recv(1024).decode())

#  calculate the shared secret
SHARED_SECRET = pow(SERVER_P_KEY, PRIVET_KEY, protocol.P)
print('shared secret: ' + str(SHARED_SECRET))

flag = True

while flag:
    message = input()
    encrypted_message = protocol.make_message(message, SHARED_SECRET, MAC_PRIVET_KEY).encode()
    # print(f"Encrypted message sent to server: {encrypted_message}")
    my_socket.sendall(encrypted_message)

    if message == 'EXIT':
        flag = False
        break

    signature, message = protocol.decrypt_message(my_socket, SERVER_MAC_KEY, SHARED_SECRET)
    if signature:
        print(message)
    else:
        print(message)


print('close')
my_socket.close()

