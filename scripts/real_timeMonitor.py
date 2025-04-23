from scapy.all import sniff, IP
import numpy as np
import pandas as pd
import subprocess
from sklearn.preprocessing import MinMaxScaler
from statsmodels.tsa.arima.model import ARIMA
from collections import deque
import time
import socket

# Store recent packet info for rolling analysis
packet_log = deque(maxlen=100)

# Simple DNS cache to avoid repeated lookups
dns_cache = {}
def get_local_ip():
    return socket.gethostbyname(socket.gethostname())

WHITELIST = {get_local_ip()}
# Block suspicious IP
# Block suspicious IP and print its domain
# Block suspicious IP and print its domain
def is_ip_already_blocked(ip):
    # Check if there's already a rule blocking this IP
    check_command = f'Get-NetFirewallRule | Where-Object {{$_.DisplayName -eq "Block {ip}"}}'
    result = subprocess.run(
        ["powershell", "-Command", check_command],
        capture_output=True,
        text=True
    )
    return bool(result.stdout.strip())


def block_ip(ip):
    if ip in WHITELIST:
        return

    if is_ip_already_blocked(ip):
        return

    domain = resolve_domain(ip)
    command = f'New-NetFirewallRule -DisplayName "Block {ip}" -Direction Inbound -RemoteAddress {ip} -Action Block'

    try:
        subprocess.run(["powershell", "-Command", command], check=True)
        print(f"Blocked IP: {ip} ({domain})")
    except subprocess.CalledProcessError as e:
        print(f"Failed to block {ip} ({domain}): {e}")


# Resolve IP to domain using reverse DNS lookup
def resolve_domain(ip):
    if ip in dns_cache:
        return dns_cache[ip]
    try:
        domain = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        domain = "Unknown"
    dns_cache[ip] = domain
    return domain

# Anomaly detection using rolling packet sizes
def detect_anomalies():
    df = pd.DataFrame(packet_log, columns=["Timestamp", "Length", "SrcIP"])
    if len(df) < 30:
        return []  # Not enough data

    mean, std = df["Length"].mean(), df["Length"].std()
    df["Anomaly"] = df["Length"].apply(lambda x: abs(x - mean) > 2 * std)
    anomalies = df[df["Anomaly"]]

    for _, row in anomalies.iterrows():
        block_ip(row["SrcIP"])

    return anomalies

# Called for every sniffed packet
def process_packet(pkt):
    if IP in pkt:
        ts = time.time()
        length = len(pkt)
        src_ip = pkt[IP].src
        domain = resolve_domain(src_ip)

        print(f"IP: {src_ip} | Domain: {domain} | Length: {length}")
        packet_log.append([ts, length, src_ip])

        if len(packet_log) % 10 == 0:
            detect_anomalies()

# Start sniffing from a network interface
def start_sniffing(interface="Wi-Fi"):  # Change this to your actual interface name
    print(f"Sniffing on {interface}... Press Ctrl+C to stop.")
    sniff(iface=interface, prn=process_packet, store=False)

if __name__ == "__main__":
    start_sniffing()
