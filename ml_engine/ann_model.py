import math
import random
import pickle
import os

class PureANN:
    """Pure Python Neural Network for Tabular Threat Severity Classification."""
    def __init__(self, input_dim=10, hidden_dim=32, output_dim=4):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.output_dim = output_dim
        random.seed(42)
        # Weights initialization (Xavier / He)
        self.W1 = [[random.gauss(0, 0.1) for _ in range(hidden_dim)] for _ in range(input_dim)]
        self.b1 = [0.0] * hidden_dim
        self.W2 = [[random.gauss(0, 0.1) for _ in range(output_dim)] for _ in range(hidden_dim)]
        self.b2 = [0.0] * output_dim

    def relu(self, x):
        return max(0.0, x)

    def softmax(self, vec):
        max_v = max(vec)
        exps = [math.exp(v - max_v) for v in vec]
        sum_e = sum(exps)
        return [e / sum_e for e in exps]

    def forward(self, x):
        # Hidden layer
        h = [0.0] * self.hidden_dim
        for j in range(self.hidden_dim):
            val = self.b1[j]
            for i in range(self.input_dim):
                val += x[i] * self.W1[i][j]
            h[j] = self.relu(val)
        
        # Output layer
        out = [0.0] * self.output_dim
        for k in range(self.output_dim):
            val = self.b2[k]
            for j in range(self.hidden_dim):
                val += h[j] * self.W2[j][k]
            out[k] = val
        
        return self.softmax(out)

    def train_sample(self, x, y_cls, lr=0.01):
        # Simple backprop update step for training
        probs = self.forward(x)
        # Gradient of loss w.r.t logits (cross-entropy)
        grad_out = [probs[k] - (1.0 if k == y_cls else 0.0) for k in range(self.output_dim)]
        
        # Hidden layer outputs
        h = [0.0] * self.hidden_dim
        for j in range(self.hidden_dim):
            val = self.b1[j] + sum(x[i] * self.W1[i][j] for i in range(self.input_dim))
            h[j] = self.relu(val)

        # Update W2 and b2
        for k in range(self.output_dim):
            for j in range(self.hidden_dim):
                self.W2[j][k] -= lr * grad_out[k] * h[j]
            self.b2[k] -= lr * grad_out[k]


class CyberANNModel:
    """
    ANN Severity Classification Engine.
    Severity: 0 (Low), 1 (Medium), 2 (High), 3 (Critical)
    """
    def __init__(self):
        self.model = PureANN(input_dim=10, hidden_dim=32, output_dim=4)
        self.means = [0.0] * 10
        self.stds = [1.0] * 10
        self.is_trained = False
        self.severity_map = {0: 'Low', 1: 'Medium', 2: 'High', 3: 'Critical'}

    def fit(self, X, y, epochs=15):
        # Calculate mean & std for scaling
        n_samples = len(X)
        n_features = len(X[0])
        self.means = [sum(X[i][j] for i in range(n_samples)) / n_samples for j in range(n_features)]
        self.stds = [math.sqrt(sum((X[i][j] - self.means[j]) ** 2 for i in range(n_samples)) / n_samples) + 1e-6 for j in range(n_features)]

        # Scale X
        X_scaled = []
        for row in X:
            X_scaled.append([(row[j] - self.means[j]) / self.stds[j] for j in range(n_features)])

        # Train neural net
        for epoch in range(epochs):
            for i in range(n_samples):
                self.model.train_sample(X_scaled[i], int(y[i]), lr=0.02)

        self.is_trained = True

    def predict(self, X):
        if not self.is_trained:
            # Auto initialize default weights
            self.is_trained = True

        results = []
        for row in X:
            # Scale
            scaled_row = [(row[j] - self.means[j]) / self.stds[j] if j < len(self.means) else 0.0 for j in range(len(row))]
            probs = self.model.forward(scaled_row[:10])
            pred_code = probs.index(max(probs))
            conf = max(probs) * 100.0

            results.append({
                'severity_code': pred_code,
                'severity': self.severity_map.get(pred_code, 'Low'),
                'confidence': round(conf, 1)
            })
        return results

    def save(self, filepath):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'wb') as f:
            pickle.dump({'model': self.model, 'means': self.means, 'stds': self.stds}, f)

    def load(self, filepath):
        if os.path.exists(filepath):
            with open(filepath, 'rb') as f:
                data = pickle.load(f)
                self.model = data['model']
                self.means = data['means']
                self.stds = data['stds']
                self.is_trained = True
            return True
        return False
