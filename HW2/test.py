import socket

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
    if data.strip() == b"\r\n\r\n\r\n\r\n":
        conn.sendall(b"generic reply")
    else:
        # Ignore everything else (HTTP GET, banner requests, etc.)
        pass
    
    conn.close()