from scapy.all import rdpcap, IP
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

def extract_features(packets):
    data, labels = [], []
    for pkt in packets:
        length = len(pkt)
        layers = len(pkt.layers())
        proto_name = pkt.payload.name if hasattr(pkt, "payload") else "None"
        proto_num = {"IP": 1, "ARP": 2, "Ethernet": 3, "IPv6": 4}.get(proto_name, 0)
        raw = sum(bytes(pkt)[:20]) if len(pkt) >= 20 else 0
        label = 1 if IP in pkt else 0
        data.append([length, layers, proto_num, raw])
        labels.append(label)
    return np.array(data), np.array(labels)

def train_model():
    packets = rdpcap("data/raw/evidence03.pcap")
    X, y = extract_features(packets)
    pd.DataFrame(X, columns=["Length", "Layers", "Protocol", "ByteSum"]).to_csv("data/labeled/ip_packet_features.csv", index=False)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    clf = RandomForestClassifier(n_estimators=100)
    clf.fit(X_train, y_train)

    print("Classification Report:\n", classification_report(y_test, clf.predict(X_test)))
    joblib.dump(clf, "models/rf_ip_classifier.pkl")
    print("Model saved as models/rf_ip_classifier.pkl")

if __name__ == "__main__":
    train_model()
