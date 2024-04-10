from scapy.all import *
import time

# Define the function to detect ICMP Echo Request floods
def detect_ping_flood(pkt_list, threshold=100, window=10):
    start_time = time.time()
    count = 0
    for pkt in pkt_list:
        if ICMP in pkt and pkt[ICMP].type == 8:  # Check if the packet is ICMP Echo Request (ping)
            count += 1
    elapsed_time = time.time() - start_time
    if elapsed_time >= window:  # Check if the time window has elapsed
        if count >= threshold:  # Check if the number of packets exceeds the threshold
            print("Potential ping flood detected! Packets received:", count)
            # Add code here to trigger an alert or take other actions
    return count

# Define the callback function for packet sniffing
def packet_callback(pkt):
    pkt_list.append(pkt)
    detect_ping_flood(pkt_list)

# Initialize the list to store received packets
pkt_list = []

# Start sniffing traffic on the specified interface
sniff(iface="en0", filter="icmp", prn=packet_callback)