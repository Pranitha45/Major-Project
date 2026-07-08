import socket

HOST = 'localhost'
PORT = 4444

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.settimeout(5)

try:
    client.connect((HOST, PORT))
    client.send('request'.encode())

    # Receive full response in chunks
    chunks = []
    while True:
        try:
            chunk = client.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        except socket.timeout:
            break

    data = b''.join(chunks).decode()
    print('Received from server:\n' + data)
finally:
    client.close()
