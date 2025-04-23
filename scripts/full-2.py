import os
import joblib
import socket
import subprocess
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from scapy.all import rdpcap, IP, TCP, UDP, ARP
from sklearn.preprocessing import MinMaxScaler
from statsmodels.tsa.arima.model import ARIMA

def get_local_ip():
    return socket.gethostbyname(socket.gethostname())

WHITELIST = {get_local_ip()}

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

def block_ip(ip):
    command = f'New-NetFirewallRule -DisplayName "Block {ip}" -Direction Inbound -RemoteAddress {ip} -Action Block'
    try:
        subprocess.run(["powershell", "-Command", command], check=True)
        print(f"Blocked IP: {ip}")
    except subprocess.CalledProcessError as e:
        print(f" Failed to block IP: {ip}, Error: {e}")

def extract_for_forecast(pcap_path):
    pkts = rdpcap(pcap_path)
    data = [[float(pkt.time), len(pkt)] for pkt in pkts if IP in pkt]
    df = pd.DataFrame(data, columns=["Timestamp", "Packet_Length"])
    df["Timestamp"] -= df["Timestamp"].iloc[0]
    return df, pkts

def detect_anomalies(df):
    mean, std = df["Packet_Length"].mean(), df["Packet_Length"].std()
    df["Anomaly"] = df["Packet_Length"].apply(lambda x: abs(x - mean) > 2 * std)
    print(f"Anomalies found at timestamps:\n{df[df['Anomaly']]['Timestamp'].values}")
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

def block_anomalous_ips(df_forecast, packets):
    anomaly_timestamps = df_forecast[df_forecast["Anomaly"]]["Timestamp"].values
    if len(anomaly_timestamps) == 0:
        print("No anomalies to match.")
        return

    print(f"🔍 Matching {len(anomaly_timestamps)} anomalies to packets...")

    matched_ips = set()
    base_time = packets[0].time

    pkt_data = []
    for pkt in packets:
        if IP in pkt:
            pkt_rel_time = pkt.time - base_time
            src_ip = pkt[IP].src
            pkt_data.append((pkt_rel_time, src_ip))

    for anomaly_time in anomaly_timestamps:
        print(f"\nChecking anomaly at {anomaly_time:.2f}s:")
        close_matches = [
            (abs(pkt_time - anomaly_time), pkt_time, src_ip)
            for pkt_time, src_ip in pkt_data
            if abs(pkt_time - anomaly_time) < 5  # 5-second window
        ]

        if close_matches:
            close_matches.sort()
            for _, pkt_time, src_ip in close_matches:
                if src_ip not in matched_ips:
                    matched_ips.add(src_ip)
                    print(f"Matched IP {src_ip} at packet time {pkt_time:.2f}s (Δ={abs(pkt_time - anomaly_time):.2f}s)")
        else:
            print(f"No packets found within ±5s of {anomaly_time:.2f}s")

    if not matched_ips:
        print("No IPs matched for blocking.")
    else:
        for ip in matched_ips:
            print(f"➡️ Blocking IP: {ip}")
            block_ip(ip)



def full_analysis():
    pcap_file = "data/raw/synthetic_traffic.pcap"
    print("\nForecasting traffic & detecting anomalies...")
    df, packets = extract_for_forecast(pcap_file)
    print(f"Total packets loaded: {len(packets)}")
    df = detect_anomalies(df)
    pred = forecast(df)
    plot(df, pred)
    block_anomalous_ips(df, packets)

if __name__ == "__main__":
    full_analysis()
