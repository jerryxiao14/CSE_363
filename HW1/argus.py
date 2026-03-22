import argparse
from datetime import datetime
from scapy.all import sniff, rdpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw 
from scapy.layers.dns import DNS, DNSQR
import re


PATTERNS = [
    re.compile(r"curl",re.I),
    re.compile(r"wget",re.I),
    re.compile(r"python",re.I),

]

"""
timestamp = datetime.fromtimestamp(pkt.time).strftime(
        "%Y-%m-%d %H:%M:%S.%f"
    )

    src_ip = pkt[IP].src 
    dst_ip = pkt[IP].dst 

    if TCP in pkt:
        proto = "TCP"
        src_port = pkt[TCP].sport 
        dst_port = pkt[TCP].dport
    elif UDP in pkt:
        proto = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport 
    else:
        return 

    print(f'{timestamp} {proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port}')
"""

INTERNAL_TLDS = (".local",".corp",".internal")
def process_packet(pkt):
    #print(pkt.summary())
    if IP not in pkt:
        return 
    if handle_http(pkt):
        return 
    
    if handle_tls(pkt):
        return 
    if handle_dns(pkt):
        return 


def handle_dns(pkt):
    if DNS not in pkt:
        return False 
    
    dns = pkt[DNS]

    if dns.qr!=0:
        return False 

    if dns.qdcount==0:
        return False 
    
    q = dns.qd
    
    if q.qtype!=1:
        return False  
    
    name = q.qname.decode(errors="ignore").rstrip('.')

    timestamp = datetime.fromtimestamp(float(pkt.time)).strftime("%Y-%m-%d %H:%M:%S.%f")
    
    src_ip = pkt[IP].src 
    dst_ip = pkt[IP].dst 

    src_port = pkt[UDP].sport 
    dst_port = pkt[UDP].dport 

    if name.endswith(INTERNAL_TLDS):
        print(f'{timestamp} DNS {src_ip}:{src_port} -> {dst_ip}:{dst_port} {name} INTERNAL')
    else:
        print(f'{timestamp} DNS {src_ip}:{src_port} -> {dst_ip}:{dst_port} {name}')
    return True



def handle_tls(pkt):
    if TCP not in pkt or Raw not in pkt:
        return False 
    
    data = bytes(pkt[Raw].load)
    #print(f'hex is {data.hex()}')
    #pkt.show()
    #print(f'ascii preview: {data.decode(errors="ignore")}')

    if data[0]!=0x16:
        return False 
    
    if len(data)<6:
        return False 
    
    if data[5]!=0x01:
        return False 

    host_name = extract_sni(data)
    timestamp = datetime.fromtimestamp(float(pkt.time)).strftime("%Y-%m-%d %H:%M:%S.%f")

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst 

    src_port = pkt[TCP].sport
    dst_port = pkt[TCP].dport

    if host_name:
        print(f'{timestamp} TLS {src_ip}:{src_port} -> {dst_ip}:{dst_port} {host_name}')
    else:
        print(f'{timestamp} TLS {src_ip}:{src_port} -> {dst_ip}:{dst_port} NO SNI')
    return True

def extract_sni(data):
    try:
        i = 5+4+2+32

        if i>=len(data):
            return None
        sid_len = data[i]
        i+=1 
        sid = data[i:i+sid_len]
        #print(f'sid is {sid.hex()}')
        i+=sid_len

        cs_len = int.from_bytes(data[i:i+2],"big") 
        i+=2+cs_len 

        if i>=len(data):
            return None 
        comp_len = data[i]
        i+=1+comp_len 

        if i+2>len(data):
            return None 
        ext_total_len=int.from_bytes(data[i:i+2],"big")
        i+=2 

        end = i+ext_total_len

        while i+4<=end and i+4<=len(data):
            ext_type = int.from_bytes(data[i:i+2],"big")
            ext_len = int.from_bytes(data[i+2:i+4],"big")
            i+=4
            if ext_type==0:
                if i+2>len(data):
                    return None 
                list_len = int.from_bytes(data[i:i+2],"big")
                j=i+2

                if j+3>len(data):
                    return None 
                j+=1

                name_len = int.from_bytes(data[j:j+2],"big")
                j+=2 

                if j+name_len>len(data):
                    return None 
                
                hostname = data[j:j+name_len].decode(errors="ignore")
                return hostname 
            i+=ext_len
    except Exception as e:
        print(f'error processling tls: {e}')
    return None

def handle_http(pkt):
    if TCP not in pkt or Raw not in pkt:
        return False
    
    payload = pkt[Raw].load

    if not (payload.startswith(b"GET ") or payload.startswith(b"POST ") or payload.startswith(b"PUT ")):
        return False
    
    try:
        text = payload.decode(errors="ignore")
        lines = text.split("\r\n")

        request_line = lines[0].split()
        #print(f'request line is {request_line}')
        method, uri, _ = request_line 

        host = ""
        agent = ""
        for line in lines[1:]:
            if line.lower().startswith("host:"):
                host = line.split(":",1)[1].strip()
            elif line.lower().startswith("user-agent:"):
                agent = line.split(":",1)[1].strip()
        timestamp = datetime.fromtimestamp(float(pkt.time)).strftime("%Y-%m-%d %H:%M:%S.%f")
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        print_str = f'{timestamp} HTTP {src_ip}:{src_port} -> {dst_ip}:{dst_port} {host} {method} {uri} {agent}'
        #print(f'{timestamp} HTTP {src_ip}:{src_port} -> {dst_ip}:{dst_port} {host} {method} {uri} {agent}')
        for pattern in PATTERNS:
            if pattern.search(agent):
                print_str+= (f' AUTOMATION {agent}')
                break
        print(print_str)
        return True

    except Exception as e:
        print(f'error processing http: {e}')
        return False 


    
        



parser = argparse.ArgumentParser(description="Argus passive network sniffer")
parser.add_argument("-i",metavar="interface",help="Live capture from device")
parser.add_argument("-r",metavar="tracefile",help="read from tcpdump format trace")
parser.add_argument("expression",nargs="?",default="",help="Optional bpf filter expression")


args = parser.parse_args()

if args.r:
    packets = rdpcap(args.r)
    for pkt in packets:
        process_packet(pkt)
else:
    interface = args.i if args.i else "eth0"
    sniff(
        iface=interface,
        filter=args.expression,
        prn=process_packet,
        store=False
    )
