📅 KẾ HOẠCH CHI TIẾT 2 TUẦN – AI NETWORK IDS PROJECT
🎯 Mục tiêu tổng quát
Xây dựng hệ thống AI-based IDS có khả năng phát hiện traffic bất thường (suspicious) qua phân tích gói tin mạng thật (Scapy).

Mô hình dùng dataset CICIDS2018 hoặc UNSW-NB15, train bằng TensorFlow/Keras.

Có demo real-time prediction hoặc offline detection từ file PCAP.

🗓️ TUẦN 1 — XÂY DỰNG NỀN TẢNG VÀ TRAIN MODEL
Ngày 1: Khởi động & phân công vai trò
Công việc:

Tạo nhóm GitHub hoặc Google Drive chia code và tài liệu.

Chọn hướng chính: Supervised Detection bằng ML/DL.

Phân công:

Nhóm 1: Data (Xử lý CICIDS/UNSW).

Nhóm 2: Model (Xây dựng CNN/DNN, train/test).

Nhóm 3: App (Flask + Scapy real-time).

Nhóm 4: Documentation + Presentation.

Sản phẩm: file Project Plan.md (gồm: mục tiêu + timeline + roles).

Ngày 2–3: Dataset & EDA
Công việc:

Chọn CICIDS2018 (subset 500MB) hoặc UNSW-NB15 (file CSV nhẹ hơn).

Load dataset → Kiểm tra NULL, encode nhãn “BENIGN” vs “ATTACK”.

Thực hiện EDA (Exploratory Data Analysis):

Distribution of attacks

Correlation heatmap

Outlier detection

Công cụ: Pandas, Seaborn, Scikit-learn.

Sản phẩm: Notebook 01_data_preprocessing.ipynb gồm biểu đồ & thống kê.

Ngày 4: Feature Engineering
Công việc:

Chuẩn hóa dữ liệu (StandardScaler hoặc MinMaxScaler).

Giảm nhiễu, xử lý imbalance bằng SMOTE hoặc undersampling.

Lưu dữ liệu đã xử lý thành .npy hoặc .csv.

python
from sklearn.preprocessing import StandardScaler
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
Sản phẩm: thư mục data/processed chứa X_train.npy, y_train.npy.

Ngày 5: Mô hình hóa (Baseline ML)
Công việc:

Train thử RandomForest, SVM, Logistic Regression để có baseline.

Đo Accuracy, Precision, Recall.

Lưu model .pkl để so sánh.

python
from sklearn.ensemble import RandomForestClassifier
rf = RandomForestClassifier(n_estimators=100)
rf.fit(X_train, y_train)
Sản phẩm: Notebook 02_baseline_models.ipynb + kết quả so sánh bảng.

Ngày 6–7: Deep Learning Model
Công việc:

Xây dựng model DNN hoặc CNN-1D bằng Keras/TensorFlow.

Train 10–15 epochs.

Plot loss & accuracy curves.

Test trên tập validation.

Save .h5 model.

Ví dụ:

python
from tensorflow.keras import models, layers
model = models.Sequential([
    layers.Dense(128, activation='relu', input_shape=(X_train.shape[1],)),
    layers.Dropout(0.3),
    layers.Dense(64, activation='relu'),
    layers.Dense(2, activation='softmax')
])
model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
model.fit(X_train, y_train, validation_split=0.2, epochs=10)
Sản phẩm: model_dnn.h5, 03_deep_learning_model.ipynb.

🗓️ TUẦN 2 — TRIỂN KHAI THỰC TẾ & HOÀN THIỆN
Ngày 8: Đánh giá & tối ưu
Công việc:

Tạo Confusion Matrix, ROC-AUC chart, classification report.

Tối ưu bằng EarlyStopping hoặc Learning Rate Scheduler.

Ghi lại các kết quả chính để đưa vào báo cáo.

Sản phẩm: Notebook 04_model_evaluation.ipynb + biểu đồ ROC.

Ngày 9: Capture packets (Scapy hoặc file PCAP)
Công việc:

Test Scapy bắt gói mạng thật (hoặc từ file .pcap có sẵn).

Trích xuất thuộc tính cơ bản: packet length, time delta, IP source, port.

python
from scapy.all import sniff, IP, TCP
def handle_pkt(pkt):
    if IP in pkt:
        print(pkt[IP].src, '➡', pkt[IP].dst)
sniff(prn=handle_pkt, count=10)
Sản phẩm: script packet_sniffer.py hoạt động được.

Ngày 10–11: Tích hợp mô hình + dự đoán realtime
Công việc:

Load model .h5, scaler .pkl.

Real-time predict với traffic đổ về.

In ra kết quả:

text
⚠️ ATTACK detected from 192.168.x.x
✅ NORMAL traffic
Tham khảo: hướng dẫn nhanh từ Calvin Cybersecurity Python IDS.​

Sản phẩm: script realtime_ids.py.

Ngày 12: Dashboard Mini
Công việc:

Tạo Flask hoặc Streamlit app hiển thị:

Tổng số packet

Số lượng alert

Log realtime alerts

bash
pip install flask flask-socketio
python app.py
Sản phẩm: mini web dashboard (app.py + template HTML).

Ngày 13: Báo cáo & slide
Công việc:

Soạn báo cáo nhóm (~10–15 trang):

Chương 1: Tổng quan & mục tiêu

Chương 2: Dataset, công cụ

Chương 3: Mô hình & pipeline

Chương 4: Kết quả & nhận xét

Kết luận & hướng phát triển

Slide trình bày (10 trang): tóm tắt, biểu đồ, demo screenshot.

Sản phẩm: report.docx, presentation.pptx.

Ngày 14: Demo & hoàn thiện dự án
Công việc:

Test end-to-end:
Script chạy → dự đoán → in cảnh báo → hiển thị dashboard.

Chuẩn bị video demo ngắn 2 phút.

Upload lên GitHub + viết hướng dẫn trong README.md.
