import scapy.all as scapy
import pandas as pd
import joblib
from datetime import datetime

# Load pre-trained ML model (assumed trained with packet metadata)
model = joblib.load("traffic_classifier.pkl")

# Function to extract features from packets
def extract_features(packet):
    return [
        len(packet),  # Packet size
        packet.time,  # Timestamp
        1 if packet.haslayer(scapy.TCP) else 0,  # Is TCP
        1 if packet.haslayer(scapy.UDP) else 0,  # Is UDP
        1 if packet.haslayer(scapy.DNS) else 0,  # Is DNS
        1 if packet.haslayer(scapy.Raw) else 0   # Has payload
    ]

# Function to analyze packets
def process_packet(packet):
    if packet.haslayer(scapy.IP):
        features = extract_features(packet)
        df = pd.DataFrame([features], columns=["Size", "Time", "TCP", "UDP", "DNS", "Payload"])
        
        prediction = model.predict(df)[0]
        
        if prediction == 1:
            print(f"[ALERT] Suspicious Packet Detected: {datetime.now()}")
            with open("intrusion_log.txt", "a") as log:
                log.write(f"{datetime.now()} - Suspicious Packet: {packet.summary()}\n")

# Capture network packets
print("Monitoring Network Traffic...")
scapy.sniff(prn=process_packet, store=False)
