import socket
import ssl 
'''
TCP Section

s = socket.socket()
s.bind(('0.0.0.0', 3131))
s.listen(1)

print("Generic TCP server listening on port 3131...")

while True:
    conn, addr = s.accept()
    print(f"Connection from {addr}")

    # Wait for client data
    data = conn.recv(1024)
    
    # Only respond if the data looks like a generic probe
    if data == b"\r\n\r\n\r\n\r\n":
        conn.sendall(b"generic reply")
    else:
        # Ignore everything else (HTTP GET, banner requests, etc.)
        pass
    
    conn.close()
'''


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

bind_sock = socket.socket()
bind_sock.bind((HOST, PORT))
bind_sock.listen(5)
print(f"Generic TLS server listening on port {PORT}...")

while True:
    client_sock, addr = bind_sock.accept()
    print(f"Connection from {addr}")

    # Wrap socket in TLS
    tls_conn = context.wrap_socket(client_sock, server_side=True)

    # Wait for client data
    data = tls_conn.recv(1024)

    # Only respond if it's the generic probe
    if data.strip() == b"\r\n\r\n\r\n\r\n":
        tls_conn.sendall(b"generic TLS reply")

    tls_conn.close()