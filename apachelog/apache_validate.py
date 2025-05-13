import re
import joblib
import pandas as pd
import numpy as np
from tensorflow.keras.models import load_model
from sklearn.preprocessing import MinMaxScaler

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
    autoencoder = load_model('./model/autoencoder_model.keras')
    scaler = joblib.load('./model/scaler.pkl')
    label_encoders = joblib.load('./model/label_encoders.pkl')
    threshold = joblib.load('./model/reconstruction_threshold.pkl')
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

# Hàm chính
def main():
    autoencoder, scaler, label_encoders, threshold = load_components()

    # Ví dụ với log raw
    raw_logs = [
        '127.0.0.1 - - [13/May/2025:03:59:09 +0000] "GET /server-status?auto HTTP/1.1" 200 1011 "-" "Python-urllib/3.12"',
        '192.168.1.10 - - [13/May/2025:04:12:45 +0000] "POST /login HTTP/1.1" 401 234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
    ]

    log_df = convert_raw_logs_to_dataframe(raw_logs)
    if log_df.empty:
        print("Không có log hợp lệ để xử lý.")
        return

    result = predict_and_detect(log_df, autoencoder, label_encoders, scaler, threshold)
    print(result[['ip', 'datetime', 'reconstruction_error', 'anomaly']])

if __name__ == '__main__':
    main()
