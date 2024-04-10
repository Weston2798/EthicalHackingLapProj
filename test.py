import scapy.all as scapy


def analyze_packet(packet):
    if packet.haslayer(scapy.IP): #and packet[scapy.TCP].dport != 80:
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        print(f"IP packet detected: Source IP - {ip_src}, Destination IP - {ip_dst}")
        print(packet[scapy.IP].dport)
        # Add your detection logic here
        # For example, you can look for suspicious patterns, known attack signatures, etc.
        # If a suspicious pattern is detected, raise an alert or take appropriate action

def start_sniffing(interface):
    print(f"Sniffing started on interface {interface}...")
    scapy.sniff(iface=interface, prn=analyze_packet)

if __name__ == "__main__":
    interface = "en0"  # Specify the network interface to monitor
    start_sniffing(interface)
