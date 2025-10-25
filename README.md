# 🧠 AI-Based Network Intrusion Detection System (IDS)

A **real-time, AI-driven Intrusion Detection System** that monitors and classifies network traffic as *normal* or *suspicious* using Deep Learning models trained on modern intrusion detection datasets.

---

## 📖 Table of Contents
- [Project Summary](#-project-summary)
- [Objectives](#-objectives)
- [System Architecture](#-system-architecture)
- [Core Modules](#-core-modules)
- [Technologies Used](#-technologies-used)
- [Dataset Information](#-dataset-information)
- [Installation Guide](#-installation-guide)
- [Project Structure](#-project-structure)
- [How to Run](#-how-to-run)
- [Demo Scenario](#-demo-scenario)
- [Results](#-results)
- [Team Members](#-team-members)
- [Future Development](#-future-development)
- [License](#-license)

---

## 🧠 Project Summary

The **AI-Based IDS** provides a modular, end-to-end cybersecurity tool for detecting anomalies and intrusions in real-time network traffic.

✅ **Detects**: DoS, DDoS, Port Scans, Brute-force, and Botnet  
✅ **Trained on**: CICIDS2018, UNSW-NB15, and IoT attack datasets  
✅ **Real-time packet inspection**: via Scapy  
✅ **Web dashboard**: built with Flask and Chart.js  

---

## 🎯 Objectives
- Capture, analyze, and classify live network traffic  
- Train and deploy a TensorFlow-based intrusion detection model  
- Develop a web-based dashboard for real-time monitoring  
- Ensure modular and scalable system design  

---

## 🧩 System Architecture
```
┌─────────────────────┐
│ Wireshark / Scapy   │ ← Packet Capture
└──────────┬──────────┘
           │
[Preprocessing + Features]
           │
┌──────────▼──────────┐
│ TensorFlow/Keras ML │ ← Model Classification
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│ Alert & Response     │ ← Logs & Alerts
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│ Flask Dashboard      │ ← Visualization
└─────────────────────┘
```

---

## ⚙️ Core Modules

| **Module** | **Function** | **Tools** |
|-------------|---------------|-----------|
| 1️⃣ Data Collection | Capture packets or import .pcap files | Scapy, PyShark |
| 2️⃣ Preprocessing & Feature Extraction | Clean, normalize, extract features | Pandas, NumPy, Scikit-learn |
| 3️⃣ AI Detection Engine | Classify traffic using DL models | TensorFlow, Keras |
| 4️⃣ Real-time Monitoring | Continuous traffic analysis | Scapy, Threading |
| 5️⃣ Alert System | Log & notify suspicious activity | Logging, JSON |
| 6️⃣ Visualization Dashboard | Monitor IDS activity visually | Flask, Chart.js |
| 7️⃣ Evaluation Module | Evaluate performance metrics | Scikit-learn, Seaborn |

---

## 💻 Technologies Used

| **Category** | **Tools** |
|---------------|-----------|
| Programming Language | Python 3.8+ |
| AI / ML Frameworks | TensorFlow, Keras, Scikit-learn |
| Network Tools | Scapy, Wireshark, PyShark |
| Web Framework | Flask, Chart.js |
| Data Visualization | Matplotlib, Seaborn |

---

## 🗃 Dataset Information

### 📚 Primary Dataset: **CICIDS2018**
Includes benign and malicious traffic such as:
- DoS, Brute Force, Botnet, Heartbleed, Web Attack

### ⚙️ Optional Datasets:
- **UNSW-NB15** — TCP/IP layer attacks  
- **TabularIoTAttack-2024** — IoT attack simulation  
- **TON_IoT 2023** — IoT telemetry dataset  

---

## 📦 Installation Guide

### Step 1: Clone Repository
```bash
git clone https://github.com/yourteam/AI-Based-IDS.git
cd AI-Based-IDS
```

### Step 2: Setup Python Environment
```bash
python -m venv venv
source venv/bin/activate       # Linux/Mac
venv\Scripts\activate          # Windows
```

### Step 3: Install Requirements
```bash
pip install -r requirements.txt
```

### Step 4: Verify Setup
```bash
python -c "import scapy; import tensorflow; print('Setup OK!')"
```

---

## 📁 Project Structure
```
AI-Based-IDS/
├── data/
│   ├── raw/              # Wireshark .pcap / dataset CSV
│   ├── processed/        # Cleaned data
│   └── features.npy
├── models/
│   ├── best_model.h5     # Trained model
│   └── scaler.pkl
├── notebooks/
│   ├── 01_preprocessing.ipynb
│   ├── 02_training.ipynb
│   └── 03_evaluation.ipynb
├── src/
│   ├── packet_sniffer.py
│   ├── feature_extractor.py
│   ├── detection_engine.py
│   ├── realtime_ids.py
│   └── alert_system.py
├── app/
│   ├── app.py
│   └── templates/
│       └── dashboard.html
├── requirements.txt
├── README.md
└── presentation.pptx
```

---

## 🚀 How to Run

### 🧩 Option 1: Train & Evaluate Model
```bash
python notebooks/02_training.ipynb
```

### 📡 Option 2: Real-Time Detection
```bash
sudo python src/realtime_ids.py
```

### 🖥️ Option 3: Run Flask Dashboard
```bash
python app/app.py
```
Then open [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## 🎬 Demo Scenario

**Terminal 1 — Run IDS:**
```bash
sudo python src/realtime_ids.py
```

**Terminal 2 — Simulate Attack:**
```bash
nmap -sS 192.168.1.5
```

**Output Example:**
```
✅ Packet #100: 192.168.1.20 → 8.8.8.8 [TCP] - Normal
⚠️ ALERT #1: Potential Scan Attack Detected | Confidence: 95.8%
```

**Dashboard:**  
Visualizes alert count, active connections, and historical logs in real time.

---

## 📊 Results

| **Metric** | **Value** |
|-------------|------------|
| Accuracy | 94.5% |
| Precision | 91.3% |
| Recall | 92.1% |
| F1-Score | 91.7% |
| Detection Time | < 2 seconds per packet |

✅ Model: DNN (3 Hidden Layers, ReLU)  
✅ Dataset: CICIDS2018 (200k balanced samples)

---

## 👥 Team Members

| **Name** | **Role** | **Responsibilities** |
|-----------|-----------|----------------------|
| Member 1 | Team Leader / ML Engineer | Model development & tuning |
| Member 2 | Data Engineer | Data preprocessing & Wireshark capture |
| Member 3 | Backend Developer | Real-time Scapy integration |
| Member 4 | Frontend Developer | Flask dashboard, Chart.js |
| Member 5 | QA / Reporter | Testing, reporting, documentation |

---

## 🔮 Future Development

- 🔐 Add IP blacklisting & firewall auto-block  
- ☁️ Deploy IDS via Docker or Streamlit  
- 📊 Integrate with Grafana for live analytics  
- 🧬 Implement Reinforcement Learning for adaptive detection  

---

## 📜 License
This project is released under the **MIT License** — free for academic and research use.

---

### 💡 Summary
> A modular, AI-powered Intrusion Detection System for real-time and offline analysis. Ideal for research, education, and cybersecurity training — blending Deep Learning, Python, and real-world network monitoring.
