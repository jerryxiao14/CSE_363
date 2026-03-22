#!/usr/bin/env python3

import argparse
import re
from datetime import datetime

from scapy.all import sniff, rdpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw


############################
# Utility Functions
############################

def format_timestamp(pkt):
    ts = datetime.fromtimestamp(pkt.time)
    return ts.strftime("%Y-%m-%d %H:%M:%S.%f")


def print_base(pkt, proto, src_ip, src_port, dst_ip, dst_port):
    ts = format_timestamp(pkt)
    print(f"{ts} {proto:<4} {src_ip}:{src_port} -> {dst_ip}:{dst_port}", end=" ")


############################
# DNS Parsing
############################

def handle_dns(pkt):
    if pkt.haslayer(DNS) and pkt.haslayer(UDP):
        dns = pkt[DNS]

        # Only DNS queries
        if dns.qr == 0 and dns.qd is not None:
            q = dns.qd

            # A record only (type 1)
            if q.qtype == 1:
                name = q.qname.decode(errors="ignore").rstrip(".")

                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport

                print_base(pkt, "DNS", src_ip, src_port, dst_ip, dst_port)

                print(name, end="")

                if name.endswith((".local", ".corp", ".internal")):
                    print(" INTERNAL", end="")

                print()
                return True

    return False


############################
# HTTP Parsing
############################

AUTOMATION_PATTERNS = [
    re.compile(r"curl", re.I),
    re.compile(r"wget", re.I),
    re.compile(r"python", re.I),
]


def is_http_request(payload):
    return payload.startswith(b"GET ") or \
           payload.startswith(b"POST ") or \
           payload.startswith(b"PUT ")


def handle_http(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        payload = pkt[Raw].load

        if is_http_request(payload):
            try:
                text = payload.decode(errors="ignore")
                lines = text.split("\r\n")

                request_line = lines[0]
                method, uri, _ = request_line.split()

                host = ""
                user_agent = ""

                for line in lines:
                    if line.lower().startswith("host:"):
                        host = line.split(":", 1)[1].strip()
                    if line.lower().startswith("user-agent:"):
                        user_agent = line.split(":", 1)[1].strip()

                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport

                print_base(pkt, "HTTP", src_ip, src_port, dst_ip, dst_port)
                print(f"{host} {method} {uri}", end="")

                for pattern in AUTOMATION_PATTERNS:
                    if pattern.search(user_agent):
                        print(f" AUTOMATION {user_agent}", end="")
                        break

                print()
                return True

            except Exception:
                return False

    return False


############################
# TLS ClientHello Parsing
############################

def handle_tls(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        payload = pkt[Raw].load

        # TLS handshake record (0x16)
        if len(payload) > 5 and payload[0] == 0x16:
            try:
                # Handshake type ClientHello (0x01)
                if payload[5] != 0x01:
                    return False

                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport

                # Basic SNI extraction
                sni = "NO SNI"

                # Search for server_name extension (type 0x0000)
                idx = payload.find(b"\x00\x00")
                if idx != -1:
                    # Attempt to parse hostname length + value
                    try:
                        server_name_len = payload[idx+5]
                        sni = payload[idx+6:idx+6+server_name_len].decode(errors="ignore")
                    except Exception:
                        pass

                print_base(pkt, "TLS", src_ip, src_port, dst_ip, dst_port)
                print(sni)
                return True

            except Exception:
                return False

    return False


############################
# Packet Dispatcher
############################

def process_packet(pkt):
    if IP not in pkt:
        return

    # Order matters: DNS (UDP), HTTP (TCP), TLS (TCP)
    if handle_dns(pkt):
        return
    if handle_http(pkt):
        return
    if handle_tls(pkt):
        return


############################
# Main
############################

def main():
    parser = argparse.ArgumentParser(description="Argus Passive Network Sniffer")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on")
    parser.add_argument("-r", "--read", help="Read packets from pcap file")
    parser.add_argument("expression", nargs="?", default="", help="BPF filter expression")

    args = parser.parse_args()

    if args.read:
        packets = rdpcap(args.read)
        for pkt in packets:
            process_packet(pkt)
    else:
        iface = args.interface if args.interface else "eth0"
        sniff(iface=iface, filter=args.expression, prn=process_packet, store=False)


if __name__ == "__main__":
    main()