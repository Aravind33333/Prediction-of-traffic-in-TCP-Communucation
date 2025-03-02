import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Sample training data (Replace with actual traffic data if available)
data = {
    "Packet_Size": [100, 200, 1500, 50, 500, 250],
    "TCP_Flag": [1, 0, 1, 0, 1, 1],
    "UDP_Flag": [0, 1, 0, 1, 0, 0],
    "DNS_Flag": [0, 0, 1, 0, 0, 1],
    "Payload_Size": [10, 20, 300, 5, 100, 50],
    "Is_Malicious": [0, 1, 1, 0, 1, 0]  # 0 = Normal, 1 = Malicious
}

# Convert to DataFrame
df = pd.DataFrame(data)

# Split features (X) and labels (y)
X = df.drop(columns=["Is_Malicious"])
y = df["Is_Malicious"]

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train a Random Forest classifier
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Test model accuracy
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy * 100:.2f}%")

# Save the trained model
joblib.dump(model, "traffic_classifier.pkl")
print("Model saved as 'traffic_classifier.pkl'.")
