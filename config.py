import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'aegis-shield-cyber-key-9823749237'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or f'sqlite:///{os.path.join(BASE_DIR, "cyber_sec.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    MODEL_DIR = os.path.join(BASE_DIR, 'ml_engine', 'saved_models')
    ANN_MODEL_PATH = os.path.join(MODEL_DIR, 'ann_model.pkl')
    LSTM_MODEL_PATH = os.path.join(MODEL_DIR, 'lstm_model.pkl')
    CNN_MODEL_PATH = os.path.join(MODEL_DIR, 'cnn_model.pkl')
