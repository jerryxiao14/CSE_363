import socket

s = socket.socket()
s.bind(('0.0.0.0', 3131))
s.listen(1)

while True:
    conn, addr = s.accept()
    data = conn.recv(1024)  # wait for client input
    conn.sendall(b"generic reply")
    conn.close()