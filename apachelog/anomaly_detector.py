import re
import joblib
import pandas as pd
import numpy as np
from tensorflow.keras.models import load_model
from sklearn.preprocessing import MinMaxScaler
import time
from send_mail import send_alert_email

# Hàm parse raw log thành dict
def parse_log_line(log_line: str) -> dict:
    log_pattern = (
        r'(?P<ip>[\d.]+) - - '
        r'\[(?P<datetime>[^\]]+)\] '
        r'"(?P<method>\w+) (?P<path>.*?) HTTP/[\d.]+" '
        r'(?P<status>\d+) (?P<size>\d+|-) '
        r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
    )

    match = re.match(log_pattern, log_line)
    if not match:
        raise ValueError("Dòng log không hợp lệ")

    data = match.groupdict()
    data['status'] = int(data['status'])
    data['size'] = int(data['size']) if data['size'] != '-' else 0
    data['datetime'] = pd.to_datetime(data['datetime'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce')
    data['hour'] = data['datetime'].hour if not pd.isna(data['datetime']) else None
    return data

# Load model và các thành phần
def load_components():
    autoencoder = load_model('model/autoencoder_model.keras')
    scaler = joblib.load('model/scaler.pkl')
    label_encoders = joblib.load('model/label_encoders.pkl')
    threshold = joblib.load('model/reconstruction_threshold.pkl')
    return autoencoder, scaler, label_encoders, threshold

# Xử lý DataFrame chứa log đã parse
def process_log(log_df, label_encoders, scaler):
    log_df = log_df.dropna(subset=['datetime'])
    log_df['hour'] = log_df['datetime'].dt.hour

    for col in ['ip', 'method', 'path', 'referrer', 'user_agent']:
        log_df[col] = log_df[col].astype(str)
        le = label_encoders[col]
        log_df[col + '_enc'] = log_df[col].map(lambda x: le.transform([x])[0] if x in le.classes_ else -1)

    feature_columns = ['ip_enc', 'method_enc', 'path_enc', 'status', 'size', 'referrer_enc', 'user_agent_enc', 'hour']
    X = log_df[feature_columns].copy()
    X = X.replace(-1, np.nan).fillna(0)
    X_scaled = scaler.transform(X)
    return X_scaled, log_df

# Dự đoán bất thường
def predict_and_detect(log_df, autoencoder, label_encoders, scaler, threshold):
    X_scaled, df_processed = process_log(log_df, label_encoders, scaler)
    reconstructions = autoencoder.predict(X_scaled)
    reconstruction_errors = np.mean(np.square(X_scaled - reconstructions), axis=1)
    df_processed['reconstruction_error'] = reconstruction_errors
    df_processed['anomaly'] = df_processed['reconstruction_error'] > threshold
    return df_processed

# Hàm theo dõi file log
def follow_log_file(filepath):
    with open(filepath, "r", encoding='utf-8') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line.strip()

# Hàm chuyển chuỗi log thành DataFrame
def convert_raw_logs_to_dataframe(raw_logs: list) -> pd.DataFrame:
    parsed_logs = []
    for line in raw_logs:
        try:
            parsed = parse_log_line(line)
            parsed_logs.append(parsed)
        except Exception as e:
            print(f"Lỗi khi phân tích dòng log: {line}\n{e}")
    return pd.DataFrame(parsed_logs)

# Hàm giám sát real-time (đã sửa để gọi send_alert_email)
def realtime_monitor(log_path):
    autoencoder, scaler, label_encoders, threshold = load_components()
    
    # Cấu hình email
    SENDER_EMAIL = "@vku.udn.vn"  # Thay bằng email của bạn
    SENDER_PASSWORD = ""  # Thay bằng Mật khẩu ứng dụng
    RECIPIENT_EMAIL = "@gmail.com"  # Thay bằng email người nhận
    
    print("Đang giám sát log Apache real-time...")

    for raw_line in follow_log_file(log_path):
        try:
            parsed = parse_log_line(raw_line)
            df = pd.DataFrame([parsed])
            result = predict_and_detect(df, autoencoder, label_encoders, scaler, threshold)
            anomaly = result.iloc[0]['anomaly']
            recon_error = result.iloc[0]['reconstruction_error']
            if anomaly:
                print(f"[!] PHÁT HIỆN BẤT THƯỜNG: {parsed['ip']} | {parsed['path']} | RE: {recon_error:.5f}")
                # Gửi email thông báo
                send_alert_email(
                    sender_email=SENDER_EMAIL,
                    sender_password=SENDER_PASSWORD,
                    recipient_email=RECIPIENT_EMAIL,
                    log_info=parsed,
                    recon_error=recon_error
                )
            else:
                print(f"[OK] {parsed['ip']} | {parsed['path']} | RE: {recon_error:.5f}")
        except Exception as e:
            print(f"[!] Lỗi xử lý dòng log: {raw_line[:100]}...\n{e}")
            continue
#192.168.139.30 - - [14/May/2025:04:15:00 +0700] "POST /zabbix/index.php HTTP/1.1" 401 512 "http://192.168.137.30/zabbix/zabbix.php?action=script.list" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0"

if __name__ == '__main__':
    log_file_path = r"D:\Persional Projects\Deep Learning Unsupervised Anomaly Detection Model\data\access.log"
    realtime_monitor(log_file_path)