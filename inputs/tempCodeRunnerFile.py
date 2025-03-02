from scapy.all import rdpcap, IP, TCP, UDP
from collections import Counter
import socket

def get_domain(ip):
    """Resolve an IP address to a domain name using reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def analyze_pcap(file_path):
    packets = rdpcap(file_path)
    total_packets = len(packets)
    protocols = Counter()
    src_ips = Counter()
    dst_ips = Counter()
    src_ports = Counter()
    dst_ports = Counter()
    
    for packet in packets:
        if IP in packet:
            src_ips[packet[IP].src] += 1
            dst_ips[packet[IP].dst] += 1

            # Only count protocol if it's an IP packet
            protocols[packet[IP].proto] += 1
        
            if TCP in packet:
                src_ports[packet[TCP].sport] += 1
                dst_ports[packet[TCP].dport] += 1
            elif UDP in packet:
                src_ports[packet[UDP].sport] += 1
                dst_ports[packet[UDP].dport] += 1
    
    print(f"Total Packets: {total_packets}")
    print(f"Protocol Distribution: {protocols}")
    
    # Resolve domains for the top 5 source IPs
    print("\nTop Source IPs and Domains:")
    for ip, count in src_ips.most_common(5):
        print(f"{ip} ({count} packets) → {get_domain(ip)}")

    # Resolve domains for the top 5 destination IPs
    print("\nTop Destination IPs and Domains:")
    for ip, count in dst_ips.most_common(5):
        print(f"{ip} ({count} packets) → {get_domain(ip)}")

    print(f"\nTop Source Ports: {src_ports.most_common(5)}")
    print(f"Top Destination Ports: {dst_ports.most_common(5)}")

if __name__ == "__main__":
    file_path = "D:\project\inputs\evidence03.pcap"  # Replace with your pcap file path
    analyze_pcap(file_path)
