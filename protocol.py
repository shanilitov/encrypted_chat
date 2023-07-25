SIZE_FIELD = 3

PORT = 8820
P = 65521
G = 13

MAC_P = 137
MAC_Q = 151

def encrypt(message, shared_secret):
    """Encrypts the message using the shared secret key"""
    message_bytes = bytearray(message, 'utf-8')
    shared_secret_bytes = shared_secret.to_bytes(4, 'big')
    encrypted_message = bytearray()
    for i in range(len(message_bytes)):
        encrypted_message.append(message_bytes[i] ^ shared_secret_bytes[i % len(shared_secret_bytes)])
    return encrypted_message

def decrypt(encrypted_message, shared_secret):
    """Decrypts the encrypted message using the shared secret key"""
    shared_secret_bytes = shared_secret.to_bytes(4, 'big')
    decrypted_message = bytearray()
    for i in range(len(encrypted_message)):
        decrypted_message.append(encrypted_message[i] ^ shared_secret_bytes[i % len(shared_secret_bytes)])
    return decrypted_message.decode('utf-8')



def hash_function(message):
    l = len(message) ^ sum(ord(c) for c in message)
    return int.from_bytes(l.to_bytes((l.bit_length() + 7) // 8, 'big'), 'big')


def signature(message, mac_privet_key):
    return pow(hash_function(message), mac_privet_key, MAC_P * MAC_Q)

def receive_hash(signature, mac_public_key):
    return pow(signature, mac_public_key, MAC_P * MAC_Q)


def make_message(message, shared_secret, mac_privet_key):
    h = signature(message, mac_privet_key)
    h_len = str(len(str(h))).zfill(SIZE_FIELD)

    e = encrypt(message, shared_secret)
    e_len = str(len(e)).zfill(SIZE_FIELD)

    return ''.join([h_len, str(h), e_len, e.decode()])

def decrypt_message(client_socket, mac_public_key, shared_secret):
    # Find the hash
    hash_len = int(client_socket.recv(SIZE_FIELD).decode())
    message_hash = receive_hash(int(client_socket.recv(hash_len).decode()), mac_public_key)

    # Find the message
    e_len = int(client_socket.recv(SIZE_FIELD).decode())
    e = bytearray(client_socket.recv(e_len))

    message = decrypt(e, shared_secret)

    # Check the signature
    if message_hash == hash_function(message):
        return True, message
    return False, 'message might be different than what the sender sent'

