import joblib
from scapy.all import sniff, IP, TCP, UDP, get_if_list
import pandas as pd
import time
import numpy as np

# Đường dẫn model và encoder đã lưu
MODEL_PATH = "rf_model_cicids2018.joblib"
ENCODER_PATH = "label_encoder.joblib"

# Số lượng packet tối thiểu để tính toán một "flow" đơn giản
# Bạn có thể chỉnh tuỳ ý
FLOW_TIMEOUT = 5  # Thời gian tích luỹ tối đa (giây) trước khi dự đoán

COLUMNS = [
    "Dst Port",
    "Protocol",
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Fwd Pkt Len Max",
    "Fwd Pkt Len Min",
    "Fwd Pkt Len Mean",
    "Fwd Pkt Len Std",
    "Bwd Pkt Len Max",
    "Bwd Pkt Len Min",
    "Bwd Pkt Len Mean",
    "Bwd Pkt Len Std",
    "Flow Byts/s",
    "Flow Pkts/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Tot",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Tot",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Len",
    "Bwd Header Len",
    "Fwd Pkts/s",
    "Bwd Pkts/s",
    "Pkt Len Min",
    "Pkt Len Max",
    "Pkt Len Mean",
    "Pkt Len Std",
    "Pkt Len Var",
    "FIN Flag Cnt",
    "SYN Flag Cnt",
    "RST Flag Cnt",
    "PSH Flag Cnt",
    "ACK Flag Cnt",
    "URG Flag Cnt",
    "CWE Flag Count",
    "ECE Flag Cnt",
    "Down/Up Ratio",
    "Pkt Size Avg",
    "Fwd Seg Size Avg",
    "Bwd Seg Size Avg",
    "Fwd Byts/b Avg",
    "Fwd Pkts/b Avg",
    "Fwd Blk Rate Avg",
    "Bwd Byts/b Avg",
    "Bwd Pkts/b Avg",
    "Bwd Blk Rate Avg",
    "Subflow Fwd Pkts",
    "Subflow Fwd Byts",
    "Subflow Bwd Pkts",
    "Subflow Bwd Byts",
    "Init Fwd Win Byts",
    "Init Bwd Win Byts",
    "Fwd Act Data Pkts",
    "Fwd Seg Size Min",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]

print("Đang nạp mô hình từ", MODEL_PATH)
model = joblib.load(MODEL_PATH)
try:
    le = joblib.load(ENCODER_PATH)
    label_encoder_exist = True
except Exception:
    le = None
    label_encoder_exist = False

# Cấu hình tăng nhạy HTTP Flood
# - Nhân hệ số cho các đặc trưng tốc độ khi flow hướng tới HTTP(S)
# - Dùng heuristic nhẹ để cảnh báo sớm
HTTP_PORTS = {80, 443}
HTTP_RATE_SENSITIVITY = 10000000000.0  # hệ số khuếch đại rate khi Dst Port là 80/443
HTTP_HEUR_FLOW_PKTS_S = 50.0  # ngưỡng thấp cho Flow Pkts/s
HTTP_HEUR_FWD_PKTS_S = 40.0   # ngưỡng thấp cho Fwd Pkts/s
HTTP_HEUR_MAX_AVG_PKT = 800.0 # ngưỡng kích thước gói trung bình (nhỏ-vừa) thường gặp ở HTTP flood


def extract_simple_features(pkts):
    # Lọc packet có IP
    pkts_ip = [pkt for pkt in pkts if IP in pkt]
    if not pkts_ip:
        # Không có gói IP nào, tránh lỗi và cấp về dict các feature 0
        return {c: 0 for c in COLUMNS if c != 'Label'}
    features = {}
    protos = []
    src_ports, dst_ports = [], []
    pkt_lens = []
    times = []
    # Thống kê forward/bwd
    fwd_pkt_times, bwd_pkt_times = [], []
    fwd_pkt_len, bwd_pkt_len = [], []
    fwd_flags, bwd_flags = [], []
    fwd_tcp_hdr_lens, bwd_tcp_hdr_lens = [], []
    fwd_udp_hdr_lens, bwd_udp_hdr_lens = [], []
    fwd_psh_cnt, bwd_psh_cnt = 0, 0
    fwd_urg_cnt, bwd_urg_cnt = 0, 0
    fwd_act_data_pkts = 0
    fwd_seg_sizes, bwd_seg_sizes = [], []
    fwd_min_seg_size = None
    init_fwd_win, init_bwd_win = 0, 0
    got_init_fwd_win, got_init_bwd_win = False, False
    total_bytes = 0

    # Xác định chiều forward: IP src đầu tiên
    src_addr = pkts_ip[0][IP].src

    for pkt in pkts_ip:
        proto = pkt[IP].proto
        is_fwd = pkt[IP].src == src_addr
        protos.append(proto)
        pkt_lens.append(len(pkt))
        times.append(pkt.time)
        total_bytes += len(pkt)
        if is_fwd:
            fwd_pkt_times.append(pkt.time)
            fwd_pkt_len.append(len(pkt))
            if TCP in pkt:
                tcp = pkt[TCP]
                fwd_flags.append(tcp.flags)
                if hasattr(tcp, 'dataofs') and tcp.dataofs:
                    fwd_tcp_hdr_lens.append(int(tcp.dataofs) * 4)
                fwd_psh_cnt += 1 if (tcp.flags & 0x08) > 0 else 0
                fwd_urg_cnt += 1 if (tcp.flags & 0x20) > 0 else 0
                if not got_init_fwd_win and hasattr(tcp, 'window'):
                    init_fwd_win = int(tcp.window)
                    got_init_fwd_win = True
                seg_size = len(bytes(tcp.payload)) if tcp.payload else 0
                fwd_seg_sizes.append(seg_size)
                if fwd_min_seg_size is None:
                    fwd_min_seg_size = seg_size
                else:
                    fwd_min_seg_size = min(fwd_min_seg_size, seg_size)
                if seg_size > 0:
                    fwd_act_data_pkts += 1
            elif UDP in pkt:
                fwd_udp_hdr_lens.append(8)
        else:
            bwd_pkt_times.append(pkt.time)
            bwd_pkt_len.append(len(pkt))
            if TCP in pkt:
                tcp = pkt[TCP]
                bwd_flags.append(tcp.flags)
                if hasattr(tcp, 'dataofs') and tcp.dataofs:
                    bwd_tcp_hdr_lens.append(int(tcp.dataofs) * 4)
                bwd_psh_cnt += 1 if (tcp.flags & 0x08) > 0 else 0
                bwd_urg_cnt += 1 if (tcp.flags & 0x20) > 0 else 0
                if not got_init_bwd_win and hasattr(tcp, 'window'):
                    init_bwd_win = int(tcp.window)
                    got_init_bwd_win = True
                seg_size = len(bytes(tcp.payload)) if tcp.payload else 0
                bwd_seg_sizes.append(seg_size)
            elif UDP in pkt:
                bwd_udp_hdr_lens.append(8)
        if TCP in pkt:
            src_ports.append(pkt[TCP].sport)
            dst_ports.append(pkt[TCP].dport)
        elif UDP in pkt:
            src_ports.append(pkt[UDP].sport)
            dst_ports.append(pkt[UDP].dport)
    first_time = times[0]
    last_time = times[-1]
    duration = last_time - first_time if len(times) > 1 else 1e-6
    # --- Feature cơ bản ---
    features["Dst Port"] = max(dst_ports) if dst_ports else 0
    features["Protocol"] = max(set(protos), key=protos.count) if protos else 0
    features["Flow Duration"] = duration * 1e6
    features["Tot Fwd Pkts"] = len(fwd_pkt_len)
    features["Tot Bwd Pkts"] = len(bwd_pkt_len)
    features["TotLen Fwd Pkts"] = sum(fwd_pkt_len)
    features["TotLen Bwd Pkts"] = sum(bwd_pkt_len)
    features["Fwd Pkt Len Max"] = max(fwd_pkt_len) if fwd_pkt_len else 0
    features["Fwd Pkt Len Min"] = min(fwd_pkt_len) if fwd_pkt_len else 0
    features["Fwd Pkt Len Mean"] = (
        sum(fwd_pkt_len) / len(fwd_pkt_len) if fwd_pkt_len else 0
    )
    features["Fwd Pkt Len Std"] = (
        pd.Series(fwd_pkt_len).std() if len(fwd_pkt_len) > 1 else 0
    )
    features["Bwd Pkt Len Max"] = max(bwd_pkt_len) if bwd_pkt_len else 0
    features["Bwd Pkt Len Min"] = min(bwd_pkt_len) if bwd_pkt_len else 0
    features["Bwd Pkt Len Mean"] = (
        sum(bwd_pkt_len) / len(bwd_pkt_len) if bwd_pkt_len else 0
    )
    features["Bwd Pkt Len Std"] = (
        pd.Series(bwd_pkt_len).std() if len(bwd_pkt_len) > 1 else 0
    )
    # --- IAT ---
    all_iats = (
        [t2 - t1 for t1, t2 in zip(times[:-1], times[1:])] if len(times) > 1 else [0]
    )
    features["Flow IAT Mean"] = np.mean(all_iats) if all_iats else 0
    features["Flow IAT Std"] = np.std(all_iats) if all_iats else 0
    features["Flow IAT Max"] = np.max(all_iats) if all_iats else 0
    features["Flow IAT Min"] = np.min(all_iats) if all_iats else 0
    fwd_iats = (
        [t2 - t1 for t1, t2 in zip(fwd_pkt_times[:-1], fwd_pkt_times[1:])]
        if len(fwd_pkt_times) > 1
        else [0]
    )
    features["Fwd IAT Tot"] = np.sum(fwd_iats) if fwd_iats else 0
    features["Fwd IAT Mean"] = np.mean(fwd_iats) if fwd_iats else 0
    features["Fwd IAT Std"] = np.std(fwd_iats) if fwd_iats else 0
    features["Fwd IAT Max"] = np.max(fwd_iats) if fwd_iats else 0
    features["Fwd IAT Min"] = np.min(fwd_iats) if fwd_iats else 0
    bwd_iats = (
        [t2 - t1 for t1, t2 in zip(bwd_pkt_times[:-1], bwd_pkt_times[1:])]
        if len(bwd_pkt_times) > 1
        else [0]
    )
    features["Bwd IAT Tot"] = np.sum(bwd_iats) if bwd_iats else 0
    features["Bwd IAT Mean"] = np.mean(bwd_iats) if bwd_iats else 0
    features["Bwd IAT Std"] = np.std(bwd_iats) if bwd_iats else 0
    features["Bwd IAT Max"] = np.max(bwd_iats) if bwd_iats else 0
    features["Bwd IAT Min"] = np.min(bwd_iats) if bwd_iats else 0
    # --- tốc độ/ratio ---
    features["Flow Byts/s"] = total_bytes / duration if duration > 0 else 0
    features["Flow Pkts/s"] = len(pkts_ip) / duration if duration > 0 else 0
    features["Fwd Pkts/s"] = (len(fwd_pkt_len) / duration) if duration > 0 else 0
    features["Bwd Pkts/s"] = (len(bwd_pkt_len) / duration) if duration > 0 else 0
    # --- Flags (tổng 2 chiều) ---
    all_flags = list(fwd_flags) + list(bwd_flags)
    features["FIN Flag Cnt"] = sum([(f & 0x01) > 0 for f in all_flags])
    features["SYN Flag Cnt"] = sum([(f & 0x02) > 0 for f in all_flags])
    features["RST Flag Cnt"] = sum([(f & 0x04) > 0 for f in all_flags])
    features["PSH Flag Cnt"] = sum([(f & 0x08) > 0 for f in all_flags])
    features["ACK Flag Cnt"] = sum([(f & 0x10) > 0 for f in all_flags])
    features["URG Flag Cnt"] = sum([(f & 0x20) > 0 for f in all_flags])
    features["CWE Flag Count"] = sum([(f & 0x80) > 0 for f in all_flags])
    features["ECE Flag Cnt"] = sum([(f & 0x40) > 0 for f in all_flags])
    features["Fwd PSH Flags"] = int(fwd_psh_cnt)
    features["Bwd PSH Flags"] = int(bwd_psh_cnt)
    features["Fwd URG Flags"] = int(fwd_urg_cnt)
    features["Bwd URG Flags"] = int(bwd_urg_cnt)
    # --- Header lens ---
    features["Fwd Header Len"] = (
        (sum(fwd_tcp_hdr_lens) + sum(fwd_udp_hdr_lens))
        if (fwd_tcp_hdr_lens or fwd_udp_hdr_lens)
        else 0
    )
    features["Bwd Header Len"] = (
        (sum(bwd_tcp_hdr_lens) + sum(bwd_udp_hdr_lens))
        if (bwd_tcp_hdr_lens or bwd_udp_hdr_lens)
        else 0
    )
    # --- Packet size global stats ---
    features["Pkt Len Min"] = int(np.min(pkt_lens)) if pkt_lens else 0
    features["Pkt Len Max"] = int(np.max(pkt_lens)) if pkt_lens else 0
    pkt_len_mean = float(np.mean(pkt_lens)) if pkt_lens else 0.0
    pkt_len_std = float(np.std(pkt_lens)) if len(pkt_lens) > 1 else 0.0
    features["Pkt Len Mean"] = pkt_len_mean
    features["Pkt Len Std"] = pkt_len_std
    features["Pkt Len Var"] = float(pkt_len_std**2)
    features["Pkt Size Avg"] = pkt_len_mean
    # --- Segment sizes ---
    features["Fwd Seg Size Avg"] = (
        float(np.mean(fwd_seg_sizes)) if fwd_seg_sizes else features["Fwd Pkt Len Mean"]
    )
    features["Bwd Seg Size Avg"] = (
        float(np.mean(bwd_seg_sizes)) if bwd_seg_sizes else features["Bwd Pkt Len Mean"]
    )
    features["Fwd Seg Size Min"] = (
        int(fwd_min_seg_size) if fwd_min_seg_size is not None else 0
    )
    # --- Ratios ---
    features["Down/Up Ratio"] = (
        (features["Tot Bwd Pkts"] / features["Tot Fwd Pkts"])
        if features["Tot Fwd Pkts"] > 0
        else 0
    )
    # --- Subflows (approximate as whole flow) ---
    features["Subflow Fwd Pkts"] = features["Tot Fwd Pkts"]
    features["Subflow Fwd Byts"] = features["TotLen Fwd Pkts"]
    features["Subflow Bwd Pkts"] = features["Tot Bwd Pkts"]
    features["Subflow Bwd Byts"] = features["TotLen Bwd Pkts"]
    # --- Init window sizes ---
    features["Init Fwd Win Byts"] = int(init_fwd_win)
    features["Init Bwd Win Byts"] = int(init_bwd_win)
    # --- Fwd active data packets ---
    features["Fwd Act Data Pkts"] = int(fwd_act_data_pkts)

    # --- Bulk features (xấp xỉ theo burst <= 1s) ---
    def compute_bulk_avgs(pkt_times, pkt_sizes):
        if not pkt_times:
            return 0.0, 0.0, 0.0
        bulks = []  # each item: (bytes, pkts, duration)
        start_idx = 0
        for i in range(1, len(pkt_times)):
            if (pkt_times[i] - pkt_times[i - 1]) > 1.0:
                bytes_sum = int(np.sum(pkt_sizes[start_idx:i])) if pkt_sizes else 0
                pkts_cnt = i - start_idx
                duration_bulk = max(pkt_times[i - 1] - pkt_times[start_idx], 1e-6)
                bulks.append((bytes_sum, pkts_cnt, duration_bulk))
                start_idx = i
        # last bulk
        bytes_sum = int(np.sum(pkt_sizes[start_idx:])) if pkt_sizes else 0
        pkts_cnt = len(pkt_times) - start_idx
        duration_bulk = max(pkt_times[-1] - pkt_times[start_idx], 1e-6)
        bulks.append((bytes_sum, pkts_cnt, duration_bulk))
        if not bulks:
            return 0.0, 0.0, 0.0
        avg_bytes_bulk = float(np.mean([b for b, _, _ in bulks]))
        avg_pkts_bulk = float(np.mean([p for _, p, _ in bulks]))
        avg_rate_bulk = float(np.mean([(b / d) if d > 0 else 0.0 for b, _, d in bulks]))
        return avg_bytes_bulk, avg_pkts_bulk, avg_rate_bulk

    fwd_bytes_bulk_avg, fwd_pkts_bulk_avg, fwd_rate_bulk_avg = compute_bulk_avgs(
        fwd_pkt_times, fwd_pkt_len
    )
    bwd_bytes_bulk_avg, bwd_pkts_bulk_avg, bwd_rate_bulk_avg = compute_bulk_avgs(
        bwd_pkt_times, bwd_pkt_len
    )
    features["Fwd Byts/b Avg"] = fwd_bytes_bulk_avg
    features["Fwd Pkts/b Avg"] = fwd_pkts_bulk_avg
    features["Fwd Blk Rate Avg"] = fwd_rate_bulk_avg
    features["Bwd Byts/b Avg"] = bwd_bytes_bulk_avg
    features["Bwd Pkts/b Avg"] = bwd_pkts_bulk_avg
    features["Bwd Blk Rate Avg"] = bwd_rate_bulk_avg
    # --- Active/Idle metrics: segment bursts by gap threshold ---
    active_threshold = 1.0
    actives, idles = [], []
    if len(times) > 0:
        current_start = times[0]
        prev_time = times[0]
        for t in times[1:]:
            gap = t - prev_time
            if gap > active_threshold:
                actives.append(prev_time - current_start)
                idles.append(gap)
                current_start = t
            prev_time = t
        actives.append(prev_time - current_start)

    def safe_stats(arr):
        if not arr:
            return 0.0, 0.0, 0.0, 0.0
        return (
            float(np.mean(arr)),
            float(np.std(arr)),
            float(np.max(arr)),
            float(np.min(arr)),
        )

    a_mean, a_std, a_max, a_min = safe_stats(actives)
    i_mean, i_std, i_max, i_min = safe_stats(idles)
    features["Active Mean"] = a_mean
    features["Active Std"] = a_std
    features["Active Max"] = a_max
    features["Active Min"] = a_min
    features["Idle Mean"] = i_mean
    features["Idle Std"] = i_std
    features["Idle Max"] = i_max
    features["Idle Min"] = i_min
    # --- Extra diagnostics (không ảnh hưởng mô hình 78 cột) ---
    # Packet length median and dispersion
    if pkt_lens:
        features["Pkt Len Median"] = float(np.median(pkt_lens))
        mean_pl = float(np.mean(pkt_lens))
        m2 = float(np.mean([(x - mean_pl) ** 2 for x in pkt_lens]))
        m3 = float(np.mean([(x - mean_pl) ** 3 for x in pkt_lens]))
        m4 = float(np.mean([(x - mean_pl) ** 4 for x in pkt_lens]))
        if m2 > 0:
            features["Pkt Len Skewness"] = m3 / (m2**1.5)
            features["Pkt Len KurtosisExcess"] = (m4 / (m2**2)) - 3.0
        else:
            features["Pkt Len Skewness"] = 0.0
            features["Pkt Len KurtosisExcess"] = 0.0
    else:
        features["Pkt Len Median"] = 0.0
        features["Pkt Len Skewness"] = 0.0
        features["Pkt Len KurtosisExcess"] = 0.0
    # IAT median and jitter-like metrics
    features["Flow IAT Median"] = float(np.median(all_iats)) if all_iats else 0.0
    features["Fwd IAT Median"] = float(np.median(fwd_iats)) if fwd_iats else 0.0
    features["Bwd IAT Median"] = float(np.median(bwd_iats)) if bwd_iats else 0.0

    def coeff_var(arr):
        if not arr:
            return 0.0
        m = float(np.mean(arr))
        s = float(np.std(arr))
        return (s / m) if m != 0 else 0.0

    features["Flow IAT CoV"] = coeff_var(all_iats)
    features["Fwd IAT Jitter"] = (
        float(np.std(np.diff(fwd_pkt_times))) if len(fwd_pkt_times) > 2 else 0.0
    )
    features["Bwd IAT Jitter"] = (
        float(np.std(np.diff(bwd_pkt_times))) if len(bwd_pkt_times) > 2 else 0.0
    )
    # Payload bytes totals
    features["Fwd Payload Byts"] = int(np.sum(fwd_seg_sizes)) if fwd_seg_sizes else 0
    features["Bwd Payload Byts"] = int(np.sum(bwd_seg_sizes)) if bwd_seg_sizes else 0
    # Zero window counts
    features["Fwd ZeroWnd Cnt"] = sum([1 for f in fwd_flags if (f & 0) == 0 and False])
    features["Bwd ZeroWnd Cnt"] = sum([1 for f in bwd_flags if (f & 0) == 0 and False])

    # ACK-only proportion approx (ACK flag set and segment size 0)
    def ack_only_ratio(flags_list, seg_sizes):
        if not flags_list:
            return 0.0
        cnt = 0
        for flg, sz in zip(
            flags_list, seg_sizes + [0] * (len(flags_list) - len(seg_sizes))
        ):
            if (flg & 0x10) > 0 and sz == 0:
                cnt += 1
        return cnt / len(flags_list)

    features["Fwd AckOnly Ratio"] = ack_only_ratio(fwd_flags, fwd_seg_sizes)
    features["Bwd AckOnly Ratio"] = ack_only_ratio(bwd_flags, bwd_seg_sizes)

    # Handshake RTT approx: first SYN (fwd) to first SYN-ACK (bwd)
    def find_first(times_list, flags_list, mask, value):
        for t, f in zip(times_list, flags_list):
            if (f & mask) == value:
                return t
        return None

    t_syn = find_first(fwd_pkt_times, fwd_flags, 0x02, 0x02)
    t_synack = find_first(bwd_pkt_times, bwd_flags, 0x12, 0x12)
    features["TCP Handshake RTT"] = (
        (t_synack - t_syn) if (t_syn is not None and t_synack is not None) else 0.0
    )

    # Duplicate seq approximations (if seq present)
    def dup_seq_count(pkts, is_fwd_dir):
        seqs = []
        for p in pkts:
            if TCP in p and IP in p:
                if (p[IP].src == src_addr) == is_fwd_dir:
                    if hasattr(p[TCP], "seq"):
                        seqs.append(int(p[TCP].seq))
        if not seqs:
            return 0
        seen = set()
        dups = 0
        for s in seqs:
            if s in seen:
                dups += 1
            else:
                seen.add(s)
        return dups

    features["Fwd Dup Seq Cnt"] = dup_seq_count(pkts_ip, True)
    features["Bwd Dup Seq Cnt"] = dup_seq_count(pkts_ip, False)
    # TTL statistics
    ttls = [
        int(pkt[IP].ttl) for pkt in pkts_ip if IP in pkt and hasattr(pkt[IP], "ttl")
    ]
    if ttls:
        features["TTL Mean"] = float(np.mean(ttls))
        features["TTL Std"] = float(np.std(ttls))
        features["TTL Min"] = int(np.min(ttls))
        features["TTL Max"] = int(np.max(ttls))
    else:
        features["TTL Mean"] = features["TTL Std"] = 0.0
        features["TTL Min"] = features["TTL Max"] = 0
    # Entropy of packet lengths (discrete)
    try:
        from collections import Counter
        import math

        ctr = Counter(pkt_lens)
        total = sum(ctr.values())
        entropy = 0.0
        if total > 0:
            for c in ctr.values():
                p = c / total
                entropy -= p * math.log2(p)
        features["Pkt Len Entropy"] = float(entropy)
    except Exception:
        features["Pkt Len Entropy"] = 0.0
    # --- Đảm bảo đủ feature cho model ---
    for c in COLUMNS:
        if c not in features and c != "Label":
            features[c] = 0

    # --- Tăng nhạy cho HTTP(S): khuếch đại các chỉ số tốc độ nếu là TCP tới 80/443 ---
    try:
        dst_port_val = int(features.get("Dst Port", 0))
        is_http_like = (features.get("Protocol", 0) == 6) and (dst_port_val in HTTP_PORTS)
        if is_http_like and HTTP_RATE_SENSITIVITY and HTTP_RATE_SENSITIVITY != 1.0:
            for rate_col in ("Flow Byts/s", "Flow Pkts/s", "Fwd Pkts/s", "Bwd Pkts/s"):
                if rate_col in features:
                    features[rate_col] = float(features[rate_col]) * HTTP_RATE_SENSITIVITY
    except Exception:
        pass
    return features


flow_packets = []
last_flow_time = time.time()

# In ra danh sách interface mạng để bạn lựa chọn
# Nếu muốn xem lại các interface, hãy bỏ comment 2 dòng dưới đây:
# print("Các interface mạng khả dụng:")
# for idx, iface in enumerate(get_if_list()):
#     print(f"{idx}: {iface}")

# Cấu hình giao diện mạng muốn bắt (để rỗng '' hoặc None để bắt all)
IFACE = "Realtek RTL8822CE 802.11ac PCIe Adapter"  # Ví dụ: 'Wi-Fi', 'Ethernet', ...

print(f"Bắt packet realtime... (sau {FLOW_TIMEOUT} giây sẽ dự đoán 1 lần)")


def process(pkt):
    global flow_packets, last_flow_time
    flow_packets.append(pkt)
    now = time.time()
    # Chỉ sử dụng điều kiện timeout để thực hiện dự đoán
    if (now - last_flow_time) > FLOW_TIMEOUT:
        if len(flow_packets) > 0:
            features = extract_simple_features(flow_packets)

            # Đảm bảo đủ đặc trưng và đúng thứ tự model yêu cầu
            required_cols = (
                list(model.feature_names_in_)
                if hasattr(model, "feature_names_in_")
                else COLUMNS[:-1]
            )
            for c in required_cols:
                if c not in features:
                    features[c] = 0
            df = pd.DataFrame([features])[required_cols]

            # Kiểm tra thiếu đặc trưng (nếu có)
            missing_cols = [c for c in required_cols if c not in df.columns]
            if missing_cols:
                print("⚠️ Các đặc trưng còn thiếu khi dự đoán:", missing_cols)
                print("Toàn bộ cột hiện có:", list(df.columns))

            # Heuristic nhẹ: nghi ngờ HTTP flood để tăng độ nhạy hiển thị
            def is_http_flood_suspected(feat: dict) -> bool:
                try:
                    if int(feat.get("Protocol", 0)) != 6:
                        return False
                    dst_port_val = int(feat.get("Dst Port", 0))
                    if dst_port_val not in HTTP_PORTS:
                        return False
                    flow_pkts_s = float(feat.get("Flow Pkts/s", 0.0))
                    fwd_pkts_s = float(feat.get("Fwd Pkts/s", 0.0))
                    avg_pkt = float(feat.get("Pkt Size Avg", feat.get("Pkt Len Mean", 0.0)))
                    # Điều kiện lỏng để nhạy hơn
                    cond_rate = (flow_pkts_s >= HTTP_HEUR_FLOW_PKTS_S) or (fwd_pkts_s >= HTTP_HEUR_FWD_PKTS_S)
                    cond_size = (avg_pkt <= HTTP_HEUR_MAX_AVG_PKT) if avg_pkt > 0 else True
                    return cond_rate and cond_size
                except Exception:
                    return False

            http_flood_hint = is_http_flood_suspected(features)

            # Dự đoán nhãn cho flow vừa bắt được
            pred = model.predict(df)[0]
            pred_label = (
                le.inverse_transform([pred])[0] if label_encoder_exist else pred
            )

            # Lấy thời gian bắt đầu/kết thúc (nếu có packet)
            if len(flow_packets) > 0:
                start_time = time.strftime(
                    "%Y-%m-%d %H:%M:%S",
                    time.localtime(getattr(flow_packets[0], "time", time.time())),
                )
                end_time = time.strftime(
                    "%Y-%m-%d %H:%M:%S",
                    time.localtime(getattr(flow_packets[-1], "time", time.time())),
                )
                src_ip = flow_packets[0][IP].src if IP in flow_packets[0] else "?"
                dst_ip = flow_packets[0][IP].dst if IP in flow_packets[0] else "?"
            else:
                start_time = end_time = src_ip = dst_ip = "?"
            suffix = " | HTTP-flood-suspected" if http_flood_hint else ""
            print(
                f"[{end_time}] Tổng {len(flow_packets):2} pkt | Thời gian: {start_time} → {end_time} | {src_ip} → {dst_ip} | Nhãn dự đoán: {pred_label}{suffix}"
            )

            # Nếu muốn, lưu log ra file theo sự kiện bất thường
            # if pred_label != 'Benign':
            #     with open('alert_log.txt', 'a', encoding='utf-8') as f:
            #         f.write(f'[{end_time}] Cảnh báo {pred_label} trên flow gồm {len(flow_packets)} pkt\n')

            flow_packets = []
            last_flow_time = now


sniff(prn=process, store=0, iface=IFACE if IFACE else None)
