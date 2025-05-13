import pandas as pd
import re

def preprocess_log_file(input_path, output_path):
    logs = []

    pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+- - \[(?P<datetime>.*?)\]\s+'
        r'"(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (?P<path>.*?) HTTP/[\d.]+"\s+'
        r'(?P<status>\d{3})\s+(?P<size>\d+)\s+'
        r'"(?P<referrer>.*?)"\s+"(?P<user_agent>.*?)"'
    )

    with open(input_path, 'r') as f:
        for line in f:
            match = pattern.search(line)
            if match:
                logs.append(match.groupdict())

    df = pd.DataFrame(logs)
    df.to_csv(output_path, index=False)
    print(f"[✔] Saved cleaned log to: {output_path}")

# Ví dụ sử dụng
if __name__ == '__main__':
    preprocess_log_file('./data/access.log', './data/processed_access_log.csv')
