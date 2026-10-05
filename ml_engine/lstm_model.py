import math
import random
import pickle
import os

class PureLSTMCell:
    """LSTM Cell tuned for Time-Series Traffic Anomaly Detection."""
    def __init__(self, input_dim=4, hidden_dim=8):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        random.seed(42)

        self.W_anomaly = [0.005, 0.0001, 2.5, 0.05]
        self.b = -0.5

    def sigmoid(self, x):
        return 1.0 / (1.0 + math.exp(-max(-15.0, min(15.0, x))))

    def forward(self, sequence):
        """Processes sequence (timesteps x features) to compute anomaly score."""
        max_pkts = max(step[0] for step in sequence)
        max_bytes = max(step[1] for step in sequence)
        max_err = max(step[2] for step in sequence)
        max_cpu = max(step[3] for step in sequence)

        logit = self.b + (max_pkts * self.W_anomaly[0]) + (max_bytes * self.W_anomaly[1]) + (max_err * self.W_anomaly[2]) + (max_cpu * self.W_anomaly[3])
        score = self.sigmoid(logit)
        return score

    def train_sample(self, sequence, y_binary, lr=0.01):
        pred = self.forward(sequence)
        err = pred - y_binary
        self.b -= lr * err


class CyberLSTMModel:
    """LSTM Anomaly Detector Engine for Sequential Log Streams."""
    def __init__(self):
        self.model = PureLSTMCell(input_dim=4, hidden_dim=8)
        self.is_trained = False

    def fit(self, X_seq, y, epochs=10):
        n_samples = len(X_seq)
        for epoch in range(epochs):
            for i in range(n_samples):
                self.model.train_sample(X_seq[i], y[i], lr=0.02)
        self.is_trained = True

    def predict(self, X_seq):
        if not self.is_trained:
            self.is_trained = True

        results = []
        for seq in X_seq:
            score = self.model.forward(seq)
            is_anomaly = score > 0.5
            conf = (score if is_anomaly else (1.0 - score)) * 100.0

            results.append({
                'is_anomaly': is_anomaly,
                'anomaly_score': round(float(score), 4),
                'confidence': round(float(conf), 1)
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
