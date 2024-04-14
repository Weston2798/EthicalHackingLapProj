import scapy.all as scapy


def analyze_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        print(f"IP packet detected: Source IP - {ip_src}, Destination IP - {ip_dst}")
        #if isinstance(packet.payload, scapy.Raw):
        print(packet)
        

def start_detecting(interface):
    print(f"Sniffing started on interface {interface}...")
    scapy.sniff(iface=interface, prn=analyze_packet)

