# NIDS_Project

🛡️ Network Intrusion Detection System (NIDS)

A real-time Network Intrusion Detection System (NIDS) built using Python, Scapy, Flask, and Machine Learning.
This project captures live network packets, analyzes traffic behavior, detects suspicious activities, and displays alerts on a live web dashboard.

📌 Features
🔴 Real-time packet sniffing
📊 Live dashboard with alerts & statistics
🧠 Machine Learning–based intrusion detection
⚙️ Rule-based detection (DDoS, SQL Injection, Phishing)
📈 Protocol-wise and severity-wise traffic analysis
💻 Web interface using Flask + JavaScript
🪟 Windows-compatible Scapy configuration


🧠 Attack Types Detected
DDoS (Distributed Denial of Service)
SQL Injection
Phishing Attempts
Anomalous Traffic (ML-based detection)

🏗️ Project Architecture

Network Traffic
      ↓
Packet Capture (Scapy)
      ↓
Feature Extraction
      ↓
Rule-based + ML Detection
      ↓
Alert Generation
      ↓
Flask API
      ↓
Live Web Dashboard

🧪 Technologies Used

Programming Language: Python
Packet Capture: Scapy
Web Framework: Flask
Machine Learning: Scikit-learn
Frontend: HTML, CSS, JavaScript
Dataset: NSL-KDD
IDE: PyCharm
Platform: Windows


📂 Project Structure

NIDS_Project/
│
├── app.py                   # Main Flask application & packet processing
├── feature_extraction.py    # Packet feature extraction logic
├── train_simple_model.py    # ML model training using NSL-KDD dataset
├── list_ifaces.py           # Lists available network interfaces
├── index.html               # Web dashboard UI
├── style.css                # Dashboard styling
├── main.js                  # Live alerts & charts
├── README.md                # Project documentation

🚀 How to Run the Project

1️⃣ Install Dependencies

Bash
pip install flask scapy scikit-learn joblib

⚠️ Npcap must be installed on Windows (enable WinPcap compatibility).

2️⃣ Train the ML Model (Optional)

Bash
python train_simple_model.py

This generates:
model.joblib
feature_columns.json

3️⃣ Run the Application

Bash
python app.py

4️⃣ Open Dashboard
http://localhost:5000


📊 Dashboard Overview

Live alerts table
Protocol counters (TCP, UDP, ICMP)
Severity levels (Low, Medium, High)
Attack type classification
Real-time packet monitoring

🧪 Testing & Validation

Tested using live browsing traffic
Simulated attack patterns
ML model evaluated using:
Accuracy
Precision
Recall

🔮 Future Enhancements

Deep learning-based IDS
Cloud deployment
Firewall integration
Email/SMS alerts
Encrypted traffic analysis

📚 References

Scapy Documentation
NSL-KDD Dataset
Scikit-learn Documentation
Research papers on ML-based IDS

👨‍🎓 Academic Use

This project was developed as part of the MCA Minor Project
and is intended for educational and research purposes.

⭐ Author
Jerlin G George
MCA @Viswa vidyapeetham
github: 
MCA Student
GitHub: https://github.com/Jerry-dev-tech�
