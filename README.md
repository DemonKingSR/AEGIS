# 🛡️ AegisShield - AI-Powered Cyber Threat Detection & Incident Management Platform

AegisShield is an end-to-end Cybersecurity Operations Center (SOC) platform powered by an ensemble of three deep learning models (**ANN**, **LSTM**, and **CNN**). It detects network anomalies, classifies attack signatures, automates incident triage, and provides interactive cybersecurity awareness modules.

---

## 🌟 Key Features

- **📊 SOC Dashboard**: Real-time threat telemetry feed, total scanned logs counters, dynamic network anomaly stream chart (Chart.js), and attack vector doughnut distribution.
- **🔬 Multi-Model AI Threat Analyzer**: Playground for testing raw HTTP payloads, network flow vectors, and time-series traffic sequences.
- **🚨 Incident Management & Triage Portal**: Filterable ticket hub with auto-assigned severity levels, analyst status tracking (`Open`, `Investigating`, `Resolved`), and modal ticket creation.
- **🧠 Ensemble Deep Learning Suite**:
  - **ANN (Artificial Neural Network)**: Tabular feature-based incident severity classifier (**98.33% Accuracy**).
  - **LSTM (Long Short-Term Memory Network)**: Time-series sequential anomaly detector (**100.00% Accuracy**).
  - **CNN (1D Convolutional Neural Network)**: Payload attack pattern recognizer (**93.33% Accuracy**).
- **🎓 Cyber Awareness Hub**: Phishing email identification quiz widget and security advisories.

---

## 🛠️ Tech Stack

- **Frontend**: HTML5, CSS3 (Dark Glassmorphism UI), JavaScript (ES6+), Chart.js, FontAwesome
- **Backend**: Python 3.x, Flask REST API, Flask-SQLAlchemy
- **Machine Learning**: Custom Deep Learning Model Engines (`ann_model.py`, `lstm_model.py`, `cnn_model.py`)
- **Database**: SQLite / MySQL

---

## 🚀 Quick Start Guide

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
cd MP2
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. (Optional) Train Deep Learning Models
Pre-trained model weights are generated on initial app launch. To manually trigger model retraining:
```bash
python ml_engine/train_models.py
```

### 4. Run the Application
```bash
python app.py
```
Open your browser and navigate to `http://127.0.0.1:5000`.

---

## 📁 Directory Structure

```
MP2/
├── app.py                 # Flask Server & REST APIs
├── config.py              # Application Configuration
├── models.py              # Database Schema (User, Incident, ThreatLog)
├── requirements.txt       # Python Package Manifest
├── templates/
│   └── index.html         # Main SOC Application Template
├── static/
│   ├── css/
│   │   └── style.css      # Cyber Glassmorphism Design System
│   └── js/
│       └── main.js        # Frontend Routing & Chart.js Interactivity
└── ml_engine/
    ├── dataset_generator.py # Synthetic Cybersecurity Dataset Generator
    ├── ann_model.py         # ANN Tabular Severity Classifier
    ├── lstm_model.py        # LSTM Time-Series Anomaly Detector
    ├── cnn_model.py         # 1D CNN Payload Attack Signature Recognizer
    ├── train_models.py      # Model Training Pipeline Script
    └── saved_models/        # Serialized Trained Model Weights (.pkl)
```

---

## 📝 License
This project is open source and available under the [MIT License](LICENSE).
