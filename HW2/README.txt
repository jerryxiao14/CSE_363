tcpscan is a TCP SYN scanner with service fingerprinting.
It identifies open ports using SYN scanning and classifies
services into 6 types based on server/client-initiated behavior
over TCP and TLS.


steps of tcpscan are as follows:
1. Perform TCP SYN scan using Scapy to identify open ports.
2. For each open port:
   - Attempt TLS connection first.
   - If TLS succeeds:
       a. Try to receive server-initiated data (Type 2)
       b. Send HTTP GET request (Type 4)
       c. Send generic probe (Type 6)
   - If TLS fails:
       a. Try to receive server-initiated data (Type 1)
       b. Send HTTP GET request (Type 3)
       c. Send generic probe (Type 5)
3. Responses are truncated to 1024 bytes.
4. Non-printable bytes are replaced with '.'.
5. CN is extracted from TLS certificates when available.

Example outputs:

running "sudo python3 tcpscan.py -p 853 8.8.8.8" gives 

Host: 8.8.8.8:553
Type: (6) Generic TLS server | CN dns.google.com 
Response: none 

running "sudo python3 tcpscan.py -p 993 imap.gmail.com" gives 

Host: imap.gmail.com:993
Type: (2) TLS server-initiated | CN imap.gmail.com 
Response: * OK Gimap ready for requests from 130.245.192.11 d75a77b69052e-50b35f85cbfmb1068357721cf ..