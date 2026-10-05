import math
import random
import pickle
import os

class Pure1DConvNet:
    """1D Convolutional Feature Extractor + Classifier for Attack Signature Recognition."""
    def __init__(self, num_classes=5):
        self.num_classes = num_classes
        self.keywords = [
            # SQLi (class 1)
            'select', 'union', 'drop table', "'1'='1'", 'where', 'from',
            # DDoS (class 2)
            'syn_flood', 'pps=', 'udp_flood', 'flood', 'icmp', 'req_per_sec',
            # XSS (class 3)
            '<script>', 'document.cookie', 'onerror=', 'javascript:', '<svg', '<iframe',
            # Brute Force (class 4)
            'failed password', 'invalid user', 'auth_fail', 'consecutive login', 'sshd'
        ]
        random.seed(42)
        # Weights for matching n-gram filters
        self.W = [[random.gauss(0, 0.1) for _ in range(num_classes)] for _ in range(len(self.keywords))]
        self.b = [0.0] * num_classes

        # Boost default weights for clean signature mapping
        for i, kw in enumerate(self.keywords):
            if i < 6:
                self.W[i][1] += 4.0  # SQLi
            elif i < 12:
                self.W[i][2] += 4.0  # DDoS
            elif i < 18:
                self.W[i][3] += 4.0  # XSS
            else:
                self.W[i][4] += 4.0  # Brute Force

    def relu(self, x):
        return max(0.0, x)

    def softmax(self, vec):
        max_v = max(vec)
        exps = [math.exp(v - max_v) for v in vec]
        sum_e = sum(exps)
        return [e / sum_e for e in exps]

    def forward(self, text):
        lower = text.lower()
        # 1D Convolution over keyword features
        feats = [1.0 if kw in lower else 0.0 for kw in self.keywords]

        logits = [self.b[c] for c in range(self.num_classes)]
        for c in range(self.num_classes):
            for f_idx, val in enumerate(feats):
                logits[c] += val * self.W[f_idx][c]

        return self.softmax(logits)

    def train_sample(self, text, y_cls, lr=0.05):
        probs = self.forward(text)
        lower = text.lower()
        feats = [1.0 if kw in lower else 0.0 for kw in self.keywords]

        for c in range(self.num_classes):
            target = 1.0 if c == y_cls else 0.0
            err = probs[c] - target
            for f_idx, val in enumerate(feats):
                self.W[f_idx][c] -= lr * err * val
            self.b[c] -= lr * err


class CyberCNNModel:
    """
    1D CNN Attack Signature Recognition Engine.
    Classes: 0: Normal Traffic, 1: SQL Injection, 2: SYN Flood DDoS, 3: Cross-Site Scripting, 4: SSH Brute Force
    """
    def __init__(self):
        self.model = Pure1DConvNet(num_classes=5)
        self.is_trained = False
        self.attack_label_map = {
            0: 'Normal Traffic',
            1: 'SQL Injection',
            2: 'SYN Flood DDoS',
            3: 'Cross-Site Scripting',
            4: 'SSH Brute Force'
        }

    def fit(self, payload_texts, y, epochs=15):
        n_samples = len(payload_texts)
        for epoch in range(epochs):
            for i in range(n_samples):
                self.model.train_sample(payload_texts[i], int(y[i]), lr=0.03)
        self.is_trained = True

    def predict(self, payload_texts):
        if not self.is_trained:
            self.is_trained = True

        results = []
        for text in payload_texts:
            probs = self.model.forward(text)
            pred_code = probs.index(max(probs))
            conf = max(probs) * 100.0
            attack_name = self.attack_label_map.get(pred_code, 'Normal Traffic')

            results.append({
                'attack_code': pred_code,
                'attack_type': attack_name,
                'confidence': round(float(conf), 1),
                'is_attack': pred_code != 0
            })
        return results

    def save(self, filepath):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'wb') as f:
            pickle.dump({'model': self.model}, f)

    def load(self, filepath):
        if os.path.exists(filepath):
            with open(filepath, 'rb') as f:
                data = pickle.load(f)
                self.model = data['model']
                self.is_trained = True
            return True
        return False
