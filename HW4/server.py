
KEY = b"0123456789ABCDEF0123456789ABCDEF"

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import datetime 
import os 
import struct 
import sys 
import socket 

def decrypt(blob):
    nonce = blob[:12]
    ciphertext = blob[12:]

    aesgcm = AESGCM(KEY)

    plaintext_zip = aesgcm.decrypt(
        nonce,ciphertext,None
    )

    return plaintext_zip


def recv_exact(conn,n):
    data = b""

    while len(data) <n:
        chunk = conn.recv(n-len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        
        data+=chunk 
    return data 

def handle_client(conn,addr):
    ip = addr[0]

    timestamp = datetime.datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S"
    )


    dirname = f"{timestamp}_{ip}"

    os.makedirs(dirname,exist_ok = True)


    raw_size = recv_exact(conn,8)
    total_size = struct.unpack("!Q",raw_size)[0]


    encrypted_blob = recv_exact(conn,total_size)

    encrypted_path = os.path.join(dirname,"archive.enc")
    with open(encrypted_path,"wb") as f:
        f.write(encrypted_blob)
    

    plaintext_zip = decrypt(encrypted_blob)

    zip_path = os.path.join(dirname,"archive.zip")
    with open(zip_path,"wb") as f:
        f.write(plaintext_zip)
    
    print(f'[+] stored backup from {ip}')
    print(f'[+] directory: {dirname}')



def main():
    if len(sys.argv)!=3:
        print(f'Usage: {sys.argv[0]} <ip> <port>')

        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2])

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host,port))

        s.listen(5)
        
        print(f'[+] listening on {host}:{port}')


        while True:
            conn,addr = s.accept()

            with conn:
                print(f'[+] connection from {addr}')

                try:
                    handle_client(conn,addr)
                except Exception as e:
                    print(f'[ERROR] {e}')
if __name__ == "__main__":
    main()