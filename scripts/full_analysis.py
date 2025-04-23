import os
import joblib
import socket
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from scapy.all import rdpcap, IP, TCP, UDP, ARP
from sklearn.preprocessing import MinMaxScaler
from statsmodels.tsa.arima.model import ARIMA

#Packet Classification
def extract_features(pkt):
    length = len(pkt)
    layers = len(pkt.layers())
    proto = pkt.proto if hasattr(pkt, 'proto') else 0
    byte_sum = sum(bytes(pkt))
    return [length, layers, proto, byte_sum]

def classify_packets(pcap_file, model_path="models/rf_ip_classifier.pkl"):
    model = joblib.load(model_path)
    packets = rdpcap(pcap_file)
    features = []
    for pkt in packets:
        if hasattr(pkt, 'proto'):
            features.append(extract_features(pkt))

    df = pd.DataFrame(features, columns=["Length", "Layers", "Protocol", "ByteSum"])
    predictions = model.predict(df)
    df["Prediction"] = predictions

    os.makedirs("results", exist_ok=True)
    df.to_csv("results/predictions.csv", index=False)
    print("Packet classification complete! Saved to results/predictions.csv")

#Traffic Analysis 
def get_domain(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def extract_traffic_data(pcap_path):
    packets = rdpcap(pcap_path)
    traffic_data = []
    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            protocol = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other"
            packet_size = len(pkt)
            traffic_data.append([src_ip, dst_ip, protocol, packet_size])

    df = pd.DataFrame(traffic_data, columns=["Source_IP", "Destination_IP", "Protocol", "Packet_Size"])
    return df, packets

def detect_ddos(df):
    from collections import Counter
    src_ip_counts = Counter(df["Source_IP"])
    for ip, count in src_ip_counts.items():
        if count > 100:
            print(f"Possible DDoS from {ip} ({count} packets)")

def detect_arp_spoofing(packets):
    table = {}
    for pkt in packets:
        if ARP in pkt and pkt[ARP].op == 2:
            ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
            if ip in table and table[ip] != mac:
                print(f" ARP spoof: {ip} has conflicting MACs {table[ip]} and {mac}")
            table[ip] = mac

def analyze_traffic(pcap_path, output_csv="data/processed/network_analysis.csv"):
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    df, packets = extract_traffic_data(pcap_path)
    df.to_csv(output_csv, index=False)
    print(f"\n Traffic CSV saved at: {output_csv}")
    detect_ddos(df)
    detect_arp_spoofing(packets)

#Forecasting & Anomaly Detection
def extract_for_forecast(pcap_path):
    pkts = rdpcap(pcap_path)
    data = [[float(pkt.time), len(pkt)] for pkt in pkts if IP in pkt]
    df = pd.DataFrame(data, columns=["Timestamp", "Packet_Length"])
    df["Timestamp"] -= df["Timestamp"].iloc[0]
    return df

def detect_anomalies(df):
    mean, std = df["Packet_Length"].mean(), df["Packet_Length"].std()
    df["Anomaly"] = df["Packet_Length"].apply(lambda x: abs(x - mean) > 2 * std)
    return df

def forecast(df):
    scaler = MinMaxScaler()
    scaled = scaler.fit_transform(df["Packet_Length"].values.reshape(-1, 1))
    model = ARIMA(scaled, order=(3,1,0)).fit()
    forecasted = model.predict(start=0, end=len(df)-1)
    return scaler.inverse_transform(forecasted.reshape(-1, 1)).flatten()

def plot(df, forecast):
    os.makedirs("results", exist_ok=True)
    plt.figure(figsize=(12,6))
    plt.plot(df["Timestamp"], df["Packet_Length"], label="Actual", color="blue")
    plt.plot(df["Timestamp"], forecast, label="Predicted", color="red", linestyle="--")
    plt.scatter(df[df["Anomaly"]]["Timestamp"], df[df["Anomaly"]]["Packet_Length"], color="orange", label="Anomalies")
    plt.title("Traffic Forecast and Anomaly Detection")
    plt.xlabel("Time (s)")
    plt.ylabel("Packet Size (bytes)")
    plt.legend()
    plt.savefig("results/traffic_plot.png")
    plt.show()


def full_analysis():
    pcap_file = "data/raw/evidence03.pcap"
    print("\n Analyzing traffic...")
    analyze_traffic(pcap_file)

    print("\ Classifying packets...")
    classify_packets(pcap_file)

    print("\n Forecasting traffic & detecting anomalies...")
    df = extract_for_forecast(pcap_file)
    df = detect_anomalies(df)
    pred = forecast(df)
    plot(df, pred)

if __name__ == "__main__":
    full_analysis()
