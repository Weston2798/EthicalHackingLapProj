from scapy.all import sniff, IP, TCP

def detect_port_scan(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        tcp_sport = packet[TCP].sport
        tcp_dport = packet[TCP].dport
        
        # Check for multiple SYN packets from the same source to different ports
        if packet[TCP].flags == 2:  # SYN flag set
            print(f"Suspicious SYN packet detected from {ip_src} to port {tcp_dport}")

# Sniff packets and call detect_port_scan function for each packet
def start_detecting():
    sniff(filter="tcp", prn=detect_port_scan, store=0)
