from scapy.all import *

def packet_handler(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        data = packet[TCP].payload
        
        print(f"Source IP: {src_ip} | Source Port: {src_port}")
        print(f"Destination IP: {dst_ip} | Destination Port: {dst_port}")
        print(f"Data: {data}")
        print("-----------------------------------------------------")

# Sniff packets on a specific network interface (change 'eth0' to the appropriate interface)
sniff(iface='eth0', prn=packet_handler, filter="tcp")
