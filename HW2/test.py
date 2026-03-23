import ssl, socket

MODE = 2   # change to 2, 4, or 6

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

sock = socket.socket()
sock.bind(("0.0.0.0", 3132))
sock.listen(5)

print(f"TLS test server running in mode {MODE}")

while True:
    client_sock, addr = sock.accept()
    print(f"Connection from {addr}")

    try:
        tls_conn = context.wrap_socket(client_sock, server_side=True)

        if MODE == 2:
            # TLS server-initiated
            tls_conn.send(b"TLS banner here\n")

        elif MODE == 4:
            # HTTPS-like
            data = tls_conn.recv(1024)
            if data.startswith(b"GET"):
                tls_conn.send(b"HTTP/1.0 200 OK\r\n\r\nhello")

        elif MODE == 6:
            # Generic TLS
            data = tls_conn.recv(1024)
            # respond only to generic probe, not HTTP
            if data == b"\r\n\r\n\r\n\r\n":
                tls_conn.send(b"generic tls reply")

        tls_conn.close()

    except Exception:
        client_sock.close()