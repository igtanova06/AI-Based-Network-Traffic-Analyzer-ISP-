# 📚 AI-Based IDS – Tài liệu Resources (CICIDS2017 • Scapy • TensorFlow/Keras • Wireshark)

Tổng hợp nguồn học liệu và tham khảo phục vụ xây dựng **AI-Based Network Intrusion Detection System (IDS)** với trọng tâm là **CICIDS2017**, **Scapy**, **TensorFlow/Keras** và tích hợp **Wireshark**.  
> Lưu ý: Bạn có thể bổ sung link chính thức của từng mục vào dấu `🔗 (URL)` để thuận tiện tra cứu nội bộ dự án.

---

## 🎯 1) CICIDS2017 – Nguồn Dữ Liệu Chính

### 🔖 Dataset chính thức
- **UNB CICIDS2017 Dataset** — Nguồn chính thức từ Canadian Institute for Cybersecurity.  
  - Quy mô: ~ **2.8 triệu** mẫu traffic thu thập trong **5 ngày** (03–07/07/2017).  
  - Nhãn & tấn công: *Brute Force, Heartbleed, Botnet, DoS, DDoS, Web Attack, Infiltration*.  
  - **79 cột** (*78 đặc trưng số + 1 nhãn*).  
  - Định dạng: **PCAP** + **CSV** (flows có nhãn).  
  - 🔗 (URL)

### 🧰 Repositories & Implementations
- **Intrusion Detection CICIDS2017** — triển khai đầy đủ ML models.  
  - 🔗 (URL)
- **Kaggle – Network Intrusion Dataset** — bộ dữ liệu sẵn sàng cho training.  
  - 🔗 (URL)

### 📄 Papers & Phân tích
- **Troubleshooting CICIDS2017 – Case Study** — đánh giá chất lượng & độ tin cậy dataset.  
  - 🔗 (URL)
- **A Comprehensive Study on CIC IDS 2017** — tổng quan toàn diện.  
  - 🔗 (URL)

---

## 🐍 2) Scapy – Packet Manipulation & Analysis

### 📘 Tài liệu chính thức
- **Scapy Official Documentation** — hướng dẫn API đầy đủ.  
  - 🔗 (URL)

### 🧪 Tutorials & Guides
- **Network Traffic Analysis with Scapy** — đọc pcap, filter theo protocol, phát hiện bất thường, tích hợp ML.  
  - 🔗 (URL)
- **GeeksforGeeks – Packet Sniffing Using Scapy** — hướng dẫn cơ bản.  
  - 🔗 (URL)

**Mẫu code:**
```python
from scapy.all import sniff, wrpcap

# Sniff 5 gói TCP
capture = sniff(count=5, filter="tcp")

# Ghi ra file PCAP
wrpcap("output.pcap", capture)

# Đọc pcap offline
packets = sniff(offline="file.pcap")
print(f"Loaded {len(packets)} packets")
```

### 🎥 Video Tutorials
- **Scapy & Python – Crafting Customized Packets**  
  - 🔗 (URL)

---

## 🤖 3) TensorFlow/Keras – Deep Learning cho IDS

### 🧩 Implementations (GitHub)
- **Deep Learning for Network Traffic Classification** — DNN/Autoencoder, UNSW/CIC.  
  - 🔗 (URL)
- **Deep Learn IDS** — Dense, Conv1D, LSTM (Keras/TensorFlow).  
  - 🔗 (URL)
- **DeepIDS** — Keras-based IDS với CICIDS 2017/2018; so sánh RF/SVM.  
  - 🔗 (URL)

### 🎓 Video Courses
- **Training IDS with Keras and KDD99 – Jeff Heaton**  
  - 🔗 (URL)

### 📰 Papers & Articles
- **Intrusion Detection by Analyzing Application Layer Protocol**  
  - Gợi ý feature: packet length, source/destination, TTL, flags; Activation: Sigmoid/ReLU; ~70% accuracy.  
  - 🔗 (URL)
- **Intrusion Detection Using Neural Network with Keras (NSL-KDD)**  
  - Feature selection + classification.  
  - 🔗 (URL)

### 📘 Official Docs
- **TensorFlow Keras Guide** — API và best practices.  
  - 🔗 (URL)
- **Keras Code Examples** — ví dụ điền sẵn cho classification/autoencoder.  
  - 🔗 (URL)

---

## 🔍 4) Wireshark Integration với Python

### 🧰 Libraries & Tools
- **PyShark** — Python wrapper cho Wireshark.  
  - 🔗 (URL)
  
**Mẫu code:**
```python
import pyshark

cap = pyshark.FileCapture("example.pcap")
for packet in cap:
    print(f"Packet #{packet.number}: {packet.highest_layer}")
```

### 🧪 GitHub Projects
- **Wireshark Network Analysis Traffic** — ICMP, MPLS-Traceroute, IPv6 NDP; thống kê & trực quan hóa.  
  - 🔗 (URL)
- **Wireshark Python Network Traffic Visualization** — tích hợp Google Earth, GeoLiteCity.  
  - 🔗 (URL)

### 🎥 Video
- **Analyzing Network Traffic with Wireshark and Python**  
  - 🔗 (URL)

---

## 📊 5) Deep Learning Models cho Network Traffic

### 📄 Research Papers (Tuyển chọn)
- **Network Traffic Classification using CNN and Ant-Lion Optimization** — 1D-CNN + ALO + Fuzzy-SOM.  
  - 🔗 (URL)
- **Hybrid CNN+LSTM-based Intrusion Detection System** — IDS thời gian thực với kiến trúc lai.  
  - 🔗 (URL)
- **Real-Time Deep Learning Based Approach** — cấu trúc dữ liệu xác suất, realtime processing.  
  - 🔗 (URL)
- **Network Traffic Classification: Techniques, Datasets, and Challenges** — survey sâu rộng.  
  - 🔗 (URL)
- **Deep Learning for Network Traffic Classification** — tổng quan DL cho phân loại traffic.  
  - 🔗 (URL)
- **Explaining Deep Learning Models for Encrypted Network Traffic** — XAI cho lưu lượng mã hóa.  
  - 🔗 (URL)

### 🛠️ Implementation Guides
- **Network Traffic Classification (GitHub)** — kỹ thuật ML cho classification.  
  - 🔗 (URL)
- **Build a Network IDS with Variational Autoencoders (PyImageSearch)**  
  - 🔗 (URL)

---

## 🛡️ 6) Deep Packet Inspection (DPI) – Khái niệm & Ứng dụng

- **Deep Packet Inspection – How It Works** — phương pháp lọc gói, kỹ thuật real-time.  
  - 🔗 (URL)
- **Fortinet – What Is DPI?** — fundamentals, checkpoint analysis.  
  - 🔗 (URL)
- **AI-based DPI for AI-driven Networks** — Encrypted Traffic Intelligence (ETI); k-NN, Decision Tree, CNN/RNN/LSTM; TLS 1.3, QUIC, ESNI.  
  - 🔗 (URL)

---

## 🎓 7) Academic Resources – IDS & Adversarial Robustness

- **Supervised ML Approach to Network Intrusion Detection on CICIDS-2017**  
  - 🔗 (URL)
- **Robustness of ML against Adversarial Attacks in IDS**  
  - 🔗 (URL)
- **Network Traffic Analysis with Python** — nền tảng phân tích traffic bằng Python.  
  - 🔗 (URL)

---

## 🧩 Phụ lục – Gợi ý quy ước liên kết

Để đồng bộ và dễ tái sử dụng, đề xuất đặt liên kết trong file `links.yml` rồi auto-generate phần *Resources* trong README:
```yaml
cicids2017_official: "https://..."
scapy_docs: "https://..."
pyshark_docs: "https://..."
keras_guide: "https://..."
tensorflow_guide: "https://..."
...
```
Sau đó dùng script `tools/build_resources.py` để bơm link vào `RESOURCES.md`.

---

## ✅ Checklist tích hợp vào repo
- [ ] Tạo thư mục `resources/` và lưu `RESOURCES.md` tại đây.  
- [ ] Bổ sung link 🔗 cho các mục quan trọng (official + mirror nếu có).  
- [ ] Thêm `links.yml` và script build (tùy chọn).  
- [ ] Trỏ từ `README.md` → `resources/RESOURCES.md` bằng mục **Further Reading**.  

> **Tip**: Khi commit, dùng conventional commits, ví dụ: `docs(resources): add CICIDS2017 official + PyShark examples`.

