import argparse 
import scapy
import sys
import socket 
from scapy.all import IP, TCP, sr1, send 

DEFAULT_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 587, 853, 993, 3389, 8080]


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
            s=socket.create_connection((args.taget,port),timeout=2)
            s.settimeout(2)

            s.sendall(b"\r\n\r\n\r\n\r\n")
            data=s.recv(1024)

            print("Type: (5) Generic TCP server")
            if data:
                data=''.join(chr(b) for b in data)
                print(f'Response: {data[:1024]}\n')
            else:
                print("Response: none\n")
        except socket.timeout:
            pass
        
        print("Type: unkown (no TCP banner)")
        print("Response is none")
        s.close()
    except Exception as e:
        print(f'something wrong happened error is {e}')
        pass 
