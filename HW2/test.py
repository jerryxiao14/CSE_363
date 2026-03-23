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

sock = socket.socket()
sock.bind(("0.0.0.0", 3132))
sock.listen(5)

print("Generic TLS server listening on port 3132...")

while True:
    client_sock, addr = sock.accept()
    print(f"Connection from {addr}")

    try:
        tls_conn = context.wrap_socket(client_sock, server_side=True)

        # TYPE (6): generic TLS
        data = tls_conn.recv(1024)
        tls_conn.send(b"generic tls reply")

        tls_conn.close()

    except ssl.SSLError as e:
        print(f"Ignoring TLS error: {e}")
        client_sock.close()