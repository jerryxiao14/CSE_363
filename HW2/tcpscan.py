import argparse 
import scapy
import sys
import socket 
from scapy.all import IP, TCP, sr1, send 
import ssl

DEFAULT_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 587, 853, 993, 3389, 8080]



def get_cn(cert):
    print(f'cert is {cert}')
    try:
        print(f'subjectAltName is {cert.get("subjectAltName")}')
        for typ, val in cert.get("subjectAltName", []):
            if typ == "DNS":
                return val
    except:
        pass

    try:
        subj = cert.get("subject",[])
        print(f'subj is {subj}')
        for item in subj:
            for key,value in item:
                if key=='commonName':
                    return value 
    except:
        pass 
    return "unknown"

def probe_tls(tls_sock, target, port, cn):
    # (2)
    try:
        data = tls_sock.recv(1024)
        if data:
            print(f"Host: {target}:{port}")
            print(f"Type: (2) TLS server-initiated | CN {cn}")
            print(f"Response: {data.decode(errors='replace')[:1024]}\n")
            return True
    except:
        pass

    # (4)
    try:
        tls_sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
        data = tls_sock.recv(1024)
        if data and data.startswith(b"HTTP"):
            print(f"Host: {target}:{port}")
            print(f"Type: (4) HTTPS server | CN {cn}")
            print(f"Response: {data.decode(errors='replace')[:1024]}\n")
            return True
    except:
        pass

    # (6)
    try:
        tls_sock.sendall(b"\r\n\r\n\r\n\r\n")
        data = tls_sock.recv(1024)
    except (socket.timeout, ConnectionResetError):
        data = b""

    print(f"Host: {target}:{port}")
    print(f"Type: (6) Generic TLS server | CN {cn}")
    if data:
        print(f"Response: {data.decode(errors='replace')[:1024]}\n")
    else:
        print("Response: none\n")

    return True 

def probe_tcp(target, port):
    # (1)
    try:
        s = socket.create_connection((target, port), timeout=2)
        s.settimeout(2)

        try:
            data = s.recv(1024)
            if data:
                print(f"Host: {target}:{port}")
                print("Type: (1) TCP server-initiated")
                print(f"Response: {data.decode(errors='replace')[:1024]}\n")
                return True
        except socket.timeout:
            pass
        s.close()
    except:
        pass

    # (3)
    try:
        s = socket.create_connection((target, port), timeout=2)
        s.settimeout(2)
        s.sendall(b"GET / HTTP/1.0\r\n\r\n")

        data = s.recv(1024)
        if data and data.startswith(b"HTTP"):
            print(f"Host: {target}:{port}")
            print("Type: (3) HTTP server")
            print(f"Response: {data.decode(errors='replace')[:1024]}\n")
            return True
        s.close()
    except:
        pass

    # (5)
    try:
        s = socket.create_connection((target, port), timeout=2)
        s.settimeout(2)
        s.sendall(b"\r\n\r\n\r\n\r\n")

        data = s.recv(1024)
    except (socket.timeout, ConnectionResetError):
        data = b""

    print(f"Host: {target}:{port}")
    print("Type: (5) Generic TCP server")
    if data:
        print(f"Response: {data.decode(errors='replace')[:1024]}\n")
    else:
        print("Response: none\n")

    return True 
    


parser = argparse.ArgumentParser(prog="tcpscan",description="TCP SYN scanenr w service fingerprint")

parser.add_argument("-p",metavar="port_range",help="Port(s) to scan(e.g, 80, 400-500, 28)")
parser.add_argument("target",help="target ip address")

args = parser.parse_args()

if args.p is None:
    ports = DEFAULT_PORTS 
else:
    parts = list(args.p.split(","))
    ports = set()

    for part in parts:
        part = part.strip()
        if "-" in part:
            start,end = map(int,part.split("-"))
            
            if start>end or start<1 or end>65535:
                raise ValueError 
            for p in range(start,end+1):
                ports.add(p)
        else:
            p = int(part)
            if p<1 or p>65535:
                raise ValueError 
            ports.add(p) 


print(f'target is {args.target}')
print(f'ports are {ports}')
        
open_ports = set()

for port in ports:
    print(f'Trying to scan port {port}')
    pkt = IP(dst=args.target)/TCP(dport=port,flags="S")
    
    resp = sr1(pkt,timeout=1,verbose=0)
    if resp is None:
        # no response to syn packtet
        continue 
    if resp.haslayer(TCP):
        flags = resp[TCP].flags 
        # SYN + ACK = 0x02+0x10=0x12
        if flags==0x12:
            print(f'port {port} is open')
            open_ports.add(port)

            # send rst close connection
            rst_pkt = IP(dst=args.target)/TCP(dport=port,flags="R")
            send(rst_pkt,verbose=0)
        elif flags==0x14:
            print(f'RST received, closed')
print(f'open ports are {open_ports}')


print("\n service fingerprinting now")

for port in open_ports:
    print(f'trying port {port}')

    is_tls = False
    cn = "unknown"

    try:
        ip = args.target 
        hostname = ip 
        if ip.replace(".","").isdigit():
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = None 
        
        sock = socket.create_connection((args.target, port), timeout=2)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        server_name = args.target if not args.target.replace(".", "").isdigit() else None
        tls_sock = context.wrap_socket(sock, server_hostname=hostname)
        tls_sock.settimeout(2)

        cert = tls_sock.getpeercert()
        cn = get_cn(cert)

        is_tls = True
    except Exception:
        pass
    if is_tls:
        try:
            probe_tls(tls_sock, args.target, port, cn)
            tls_sock.close()
        except:
            print(f"Host: {args.target}:{port}")
            print(f"Type: (6) Generic TLS server | CN {cn}")
            print("Response: none\n")
        continue

# otherwise TCP
    probe_tcp(args.target, port)
    continue 
    # TLS
    cn = "unknown"

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        sock = socket.create_connection((args.target, port), timeout=2)
        tls_sock = context.wrap_socket(sock, server_hostname=args.target)
        tls_sock.settimeout(2)

        cert = tls_sock.getpeercert()
        cn = get_cn(cert)

        # (2) TLS server-initiated
        try:
            data = tls_sock.recv(1024)
            if data:
                print(f"Host: {args.target}:{port}")
                print(f"Type: (2) TLS server-initiated | CN {cn}")
                print("Response: ...\n")
                tls_sock.close()
                continue
        except:
            pass

        # (4) HTTPS
        try:
            tls_sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
            data = tls_sock.recv(1024)
            if data:
                print(f"Host: {args.target}:{port}")
                print(f"Type: (4) HTTPS server | CN {cn}")
                print("Response: ...\n")
                tls_sock.close()
                continue
        except:
            pass

        # (6) Generic TLS
        try:
            tls_sock.sendall(b"\r\n\r\n\r\n\r\n")
            data = tls_sock.recv(1024)
        except (socket.timeout, ConnectionResetError):
            data = b""

        print(f"Host: {args.target}:{port}")
        print(f"Type: (6) Generic TLS server | CN {cn}")
        print("Response: none\n")

        tls_sock.close()
        continue
    except Exception as e:
        pass
    
    # TCP
    try:
        s = socket.create_connection((args.target,port),timeout=2)
        s.settimeout(2)
        # TCP banner
        try:
            data=s.recv(1024)
            if data:
                data = ''.join(chr(b) for b in data)
                print("Type: (1) TCP server-initialted")
                print(f"Response: {data[:1024]}\n")

                s.close()
                continue 
        except socket.timeout:
            pass
        # try http now 
        try:
            s.close() 
            s = socket.create_connection((args.target,port),timeout=2)
            s.settimeout(2)
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            data = s.recv(1024)

            if data:
                data = ''.join(chr(b) for b in data)
                print(f'Type: (3) HTTP server')
                print(f"Response: {data[:1024]}\n")

                s.close()
                continue 
        except socket.timeout:
            pass
        # generic tcp
        try:
            s.close()
            s=socket.create_connection((args.target,port),timeout=2)
            s.settimeout(2)

            s.sendall(b"\r\n\r\n\r\n\r\n")
            data=s.recv(1024)

            print("Type: (5) Generic TCP server")
            if data:
                data=''.join(chr(b) for b in data)
                print(f'Response: {data[:1024]}\n')
            else:
                print("Response: none\n")
            continue 
        except (socket.timeout,ConnectionResetError):
            print(f"Type: (5) generic TCP server")
            print("Response: none\n")
            pass 
        s.close()
    except Exception as e:
        print(f'something wrong happened error is {e}')
        pass 
    
    
        
        
        
    
