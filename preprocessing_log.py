import pandas as pd
import re

def preprocess_log_file(input_path, output_path):
    messages = []

    with open(input_path, 'r') as f:
        for line in f:
            # Loại bỏ timestamp và hostname, giữ lại tiến trình + message
            match = re.search(r'^\w{3} \d{1,2} \d{2}:\d{2}:\d{2} \S+ (.+)', line)
            if match:
                message = match.group(1).strip()
                messages.append(message)

    df = pd.DataFrame(messages, columns=['message'])
    df.to_csv(output_path, index=False)
    print(f"[✔] Saved cleaned log to: {output_path}")

# Ví dụ sử dụng
if __name__ == '__main__':
    preprocess_log_file('data/remote.log', 'data/processed_log.csv')
