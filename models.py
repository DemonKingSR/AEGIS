from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(50), default='Security Analyst')  # Admin, Security Analyst, User
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }

class Incident(db.Model):
    __tablename__ = 'incidents'
    id = db.Column(db.String(50), primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    attack_category = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(50), nullable=False)  # Low, Medium, High, Critical
    source_ip = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), default='Open')  # Open, Investigating, Resolved
    assigned_to = db.Column(db.String(80), default='SecAnalyst_Root')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'attack': self.attack_category,
            'severity': self.severity,
            'ip': self.source_ip,
            'description': self.description,
            'status': self.status,
            'assigned_to': self.assigned_to,
            'created': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }

class ThreatLog(db.Model):
    __tablename__ = 'threat_logs'
    id = db.Column(db.Integer, primary_key=True)
    source_ip = db.Column(db.String(50), nullable=False)
    raw_payload = db.Column(db.Text, nullable=False)
    ann_severity = db.Column(db.String(50))
    lstm_anomaly_score = db.Column(db.Float)
    cnn_attack_type = db.Column(db.String(100))
    confidence = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'source_ip': self.source_ip,
            'payload': self.raw_payload,
            'ann_severity': self.ann_severity,
            'lstm_anomaly_score': self.lstm_anomaly_score,
            'cnn_attack_type': self.cnn_attack_type,
            'confidence': self.confidence,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        }

def seed_initial_data():
    """Populate initial seed incidents if database is empty."""
    if Incident.query.count() == 0:
        initial_incidents = [
            Incident(
                id='INC-2026-101',
                title='SQL Injection attempt on auth portal',
                attack_category='SQL Injection',
                severity='Critical',
                source_ip='203.0.113.195',
                description="Malicious SQL signature detected in HTTP body: SELECT * FROM users WHERE '1'='1'",
                status='Open'
            ),
            Incident(
                id='INC-2026-102',
                title='DDoS SYN Flood targeted at DNS server',
                attack_category='DDoS Attack',
                severity='Critical',
                source_ip='198.51.100.42',
                description="LSTM anomaly score 0.98. Traffic spike exceeding 150,000 pps.",
                status='Investigating'
            ),
            Incident(
                id='INC-2026-103',
                title='XSS payload detected in user feedback form',
                attack_category='XSS Attack',
                severity='High',
                source_ip='198.51.100.88',
                description="CNN Payload analyzer matched script tag pattern <script>document.cookie</script>",
                status='Open'
            ),
            Incident(
                id='INC-2026-104',
                title='Repeated SSH login failures on gateway',
                attack_category='Brute Force',
                severity='Medium',
                source_ip='192.168.1.105',
                description="PAM authentication failure for service sshd user admin.",
                status='Resolved'
            )
        ]
        db.session.bulk_save_objects(initial_incidents)
        db.session.commit()
        print("Database seeded with initial incidents.")
