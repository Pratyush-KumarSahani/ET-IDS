# ThreatPulse: A Two-Stage Machine Learning Intrusion Detection System

ThreatPulse is a real-time Intrusion Detection System (IDS) developed as our final-year research project. It uses Machine Learning to detect malicious network traffic by analyzing network flow metadata instead of packet payloads, making it effective even when traffic is encrypted.

The system captures live packets, extracts important flow features, classifies traffic using a two-stage XGBoost model, and displays the results through a FastAPI-based web dashboard. It also supports automatic IP blocking for detected threats.

---

## Features

- Live packet capture using Scapy
- Flow-based feature extraction
- Two-stage XGBoost detection pipeline
  - Binary classification (Benign or Malicious)
  - Attack type classification
- FastAPI dashboard with real-time updates
- Live attack logs and traffic monitoring
- Automatic IP blocking (optional)
- Windows Firewall integration
- SQLite database for storing logs
- Lightweight and runs on a normal laptop without a GPU

---

## How It Works

```
Network Traffic
      │
      ▼
Packet Capture (Scapy)
      │
      ▼
Flow Feature Extraction
      │
      ▼
Stage 1: Binary Detection
(Benign / Malicious)
      │
      ▼
Stage 2: Attack Classification
      │
      ▼
FastAPI Dashboard
      │
      ▼
Alert & IP Blocking
```

---

## Technologies Used

**Machine Learning**

- XGBoost
- Scikit-learn
- Pandas
- NumPy
- Joblib

**Backend**

- FastAPI
- Uvicorn
- WebSockets

**Packet Capture**

- Scapy
- Npcap (Windows)

**Frontend**

- HTML
- CSS
- JavaScript
- Chart.js

**Database**

- SQLite

---

## Datasets Used

The model was trained and evaluated using multiple benchmark datasets to improve its performance across different network environments.

- CICIDS2017
- NF-UNSW-NB15-v2
- NF-ToN-IoT-v2
- CICIOT2023

---

## Model Files

Place the trained model files inside the **models** folder.

```
models/
│
├── binary_pipeline.pkl
├── binary_label_encoder.pkl
├── attack_pipeline.pkl
├── attack_label_encoder.pkl
└── feature_columns.pkl
```

The application also supports the older single-model format:

```
pipeline.pkl
label_encoder.pkl
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/ThreatPulse.git
cd ThreatPulse
```

Install the required packages:

```bash
pip install -r requirements.txt
```

If you're using Windows, install **Npcap** before running live packet capture.

---

## Running the Project

Start the application using the helper script:

```powershell
.\start_ids.ps1
```

Useful options:

```powershell
.\start_ids.ps1 -OpenDashboard
.\start_ids.ps1 -CaptureInterface "Ethernet"
.\start_ids.ps1 -CaptureFilter "tcp port 443"
.\start_ids.ps1 -NoCapture
.\start_ids.ps1 -UseWindowsFirewall
```

Or run the FastAPI server manually:

```bash
uvicorn fastapi_ids_backend:app --host 0.0.0.0 --port 8000
```

Open your browser and visit:

```
http://localhost:8000
```

> Live packet capture on Windows may require Administrator privileges and Npcap.

---

## Configuration

The application allows custom model paths through environment variables.

```powershell
IDS_BINARY_MODEL_PATH
IDS_ATTACK_MODEL_PATH
IDS_BINARY_LABEL_ENCODER_PATH
IDS_ATTACK_LABEL_ENCODER_PATH
IDS_FEATURE_COLUMNS_PATH
```

To change the confidence threshold:

```powershell
$env:IDS_ATTACK_CONFIDENCE_THRESHOLD="90"
```

---

## Blocking Modes

By default, detected IP addresses are stored in the application's internal blocklist.

```powershell
$env:IDS_BLOCK_MODE="memory"
```

To automatically create Windows Firewall rules:

```powershell
$env:IDS_BLOCK_MODE="windows_firewall"
```

Administrator privileges are required for firewall mode.

---

## Performance

- **Overall Accuracy:** 99.2%
- **Average Detection Time:** ~3.5 ms per flow
- **Runs entirely on CPU**
- **Supports real-time monitoring**
- **Live dashboard with attack logs**
- **Optional automatic IP blocking**

---

## Project Workflow

1. Capture live packets from the selected network interface.
2. Convert packets into network flows.
3. Extract flow-level features.
4. Detect malicious traffic using the binary classifier.
5. Identify the attack type using the second-stage classifier.
6. Display alerts on the dashboard.
7. Store logs and optionally block malicious IP addresses.

---

## Authors

- Pratyush Kumar Sahani
- Anurag Pattanaik
- Rohan Mishra

**Faculty of Engineering & Technology (ITER)**  
**Siksha 'O' Anusandhan (Deemed to be) University**

---

## License

This project was developed as part of our final-year research work and is intended for educational and research purposes.
