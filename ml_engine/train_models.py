import os
import sys

# Ensure import paths work
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from dataset_generator import generate_cyber_tabular_dataset, generate_time_series_sequences, generate_payload_text_dataset
from ann_model import CyberANNModel
from lstm_model import CyberLSTMModel
from cnn_model import CyberCNNModel

SAVED_MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'saved_models')

def compute_accuracy(y_true, y_pred):
    correct = sum(1 for t, p in zip(y_true, y_pred) if t == p)
    return correct / len(y_true) if len(y_true) > 0 else 0.0

def train_all_models():
    print("=" * 70)
    print("      AEGISSHIELD DEEP LEARNING MODEL TRAINING PIPELINE")
    print("=" * 70)

    os.makedirs(SAVED_MODELS_DIR, exist_ok=True)

    # -------------------------------------------------------------
    # 1. Train ANN Model (Tabular Severity Classifier)
    # -------------------------------------------------------------
    print("\n[1/3] Generating Tabular Dataset & Training ANN Model...")
    df_ann, y_ann = generate_cyber_tabular_dataset(num_samples=1500)
    X_ann = df_ann.values.tolist()
    
    split_idx = int(len(X_ann) * 0.8)
    X_train_ann, X_test_ann = X_ann[:split_idx], X_ann[split_idx:]
    y_train_ann, y_test_ann = y_ann[:split_idx], y_ann[split_idx:]

    ann = CyberANNModel()
    ann.fit(X_train_ann, y_train_ann, epochs=12)

    preds_ann = ann.predict(X_test_ann)
    y_pred_ann = [p['severity_code'] for p in preds_ann]
    acc_ann = compute_accuracy(y_test_ann, y_pred_ann)

    print(f" -> ANN Model Training Complete.")
    print(f" -> Test Accuracy: {acc_ann * 100:.2f}%")
    ann.save(os.path.join(SAVED_MODELS_DIR, 'ann_model.pkl'))

    # -------------------------------------------------------------
    # 2. Train LSTM Model (Sequential Anomaly Detector)
    # -------------------------------------------------------------
    print("\n[2/3] Generating Time-Series Sequences & Training LSTM Model...")
    X_lstm, y_lstm = generate_time_series_sequences(num_sequences=1000, seq_len=10)
    split_idx_lstm = int(len(X_lstm) * 0.8)
    X_train_lstm, X_test_lstm = X_lstm[:split_idx_lstm], X_lstm[split_idx_lstm:]
    y_train_lstm, y_test_lstm = y_lstm[:split_idx_lstm], y_lstm[split_idx_lstm:]

    lstm = CyberLSTMModel()
    lstm.fit(X_train_lstm, y_train_lstm, epochs=10)

    preds_lstm = lstm.predict(X_test_lstm)
    y_pred_lstm = [1 if p['is_anomaly'] else 0 for p in preds_lstm]
    acc_lstm = compute_accuracy(y_test_lstm, y_pred_lstm)

    print(f" -> LSTM Model Training Complete.")
    print(f" -> Test Accuracy: {acc_lstm * 100:.2f}%")
    lstm.save(os.path.join(SAVED_MODELS_DIR, 'lstm_model.pkl'))

    # -------------------------------------------------------------
    # 3. Train CNN Model (1D Payload Attack Recognizer)
    # -------------------------------------------------------------
    print("\n[3/3] Generating Payload Text Corpus & Training CNN Model...")
    X_cnn, y_cnn = generate_payload_text_dataset(num_samples=1200)
    split_idx_cnn = int(len(X_cnn) * 0.8)
    X_train_cnn, X_test_cnn = X_cnn[:split_idx_cnn], X_cnn[split_idx_cnn:]
    y_train_cnn, y_test_cnn = y_cnn[:split_idx_cnn], y_cnn[split_idx_cnn:]

    cnn = CyberCNNModel()
    cnn.fit(X_train_cnn, y_train_cnn, epochs=10)

    preds_cnn = cnn.predict(X_test_cnn)
    y_pred_cnn = [p['attack_code'] for p in preds_cnn]
    acc_cnn = compute_accuracy(y_test_cnn, y_pred_cnn)

    print(f" -> CNN Model Training Complete.")
    print(f" -> Test Accuracy: {acc_cnn * 100:.2f}%")
    cnn.save(os.path.join(SAVED_MODELS_DIR, 'cnn_model.pkl'))

    print("\n" + "=" * 70)
    print(" ALL DEEP LEARNING MODELS TRAINED & SERIALIZED SUCCESSFULLY!")
    print(f" Artifact Location: {SAVED_MODELS_DIR}")
    print("=" * 70)

    return {
        'ann_acc': acc_ann,
        'lstm_acc': acc_lstm,
        'cnn_acc': acc_cnn
    }

if __name__ == '__main__':
    train_all_models()
