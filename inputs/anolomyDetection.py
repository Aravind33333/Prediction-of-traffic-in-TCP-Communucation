import pyshark
import joblib
import pandas as pd

# Load the trained model
model = joblib.load("traffic_classifier.pkl")

# Define function to extract features from packets
def extract_features_from_pcap(pcap_file):
    packets = pyshark.FileCapture(pcap_file, display_filter="ip")
    
    data = []
    for pkt in packets:
        try:
            packet_size = int(pkt.length)  # Packet size in bytes
            payload_size = int(pkt.tcp.len) if hasattr(pkt, "tcp") else 0  # TCP Payload size
            
            # Extracting protocol flags
            tcp_flag = 1 if hasattr(pkt, "tcp") else 0
            udp_flag = 1 if hasattr(pkt, "udp") else 0
            dns_flag = 1 if hasattr(pkt, "dns") else 0
            
            # Append extracted data
            data.append([packet_size, tcp_flag, udp_flag, dns_flag, payload_size])
        except AttributeError:
            continue  # Skip packets without required attributes

    packets.close()
    return data

# Path to your PCAP file
pcap_file = "D:/project/inputs/evidence03.pcap"  # Change this to your PCAP file path

# Extract features from PCAP
features = extract_features_from_pcap(pcap_file)

# Convert to DataFrame
columns = ["Packet_Size", "TCP_Flag", "UDP_Flag", "DNS_Flag", "Payload_Size"]
df = pd.DataFrame(features, columns=columns)

# Predict using trained model
if not df.empty:
    predictions = model.predict(df)
    df["Prediction"] = predictions  # Append predictions to DataFrame
    
    # Display results
    print(df)
    df.to_csv("D:/project/outputs/predictions.csv", index=False)  # Save results to CSV
    print("Predictions saved to 'D:/project/outputs/predictions.csv'")
else:
    print("No valid packets extracted from PCAP.")
