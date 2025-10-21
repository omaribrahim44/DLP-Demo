from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    sent_emails = db.relationship('EmailLog', foreign_keys='EmailLog.sender_id', backref='sender', lazy='dynamic')
    received_emails = db.relationship('EmailLog', foreign_keys='EmailLog.recipient_id', backref='recipient', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.email}>'

class EmailLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    subject = db.Column(db.String(200))
    is_blocked = db.Column(db.Boolean, default=False)
    block_reason = db.Column(db.String(500))
    policy_violations = db.Column(db.JSON)  # Store multiple policy violations
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f'<EmailLog {self.id}: {"BLOCKED" if self.is_blocked else "ALLOWED"}>'

class DLPPolicy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text)
    pattern = db.Column(db.Text, nullable=False)  # Regex pattern
    category = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<DLPPolicy {self.name}>'

class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    level = db.Column(db.String(20), nullable=False)  # INFO, WARNING, ERROR, CRITICAL
    message = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    user = db.relationship('User', backref='logs')
    
    def __repr__(self):
        return f'<SystemLog {self.level}: {self.message[:50]}...>'

class SecurityIncident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incident_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    email_log_id = db.Column(db.Integer, db.ForeignKey('email_log.id'))
    status = db.Column(db.String(20), default='open')  # open, investigating, resolved, closed
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    resolved_at = db.Column(db.DateTime)
    resolved_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    user = db.relationship('User', foreign_keys=[user_id], backref='incidents')
    email_log = db.relationship('EmailLog', backref='security_incident')
    resolver = db.relationship('User', foreign_keys=[resolved_by])
    
    def __repr__(self):
        return f'<SecurityIncident {self.incident_type}: {self.severity}>'

class FileScan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False, index=True)
    file_size = db.Column(db.Integer, nullable=False)
    mime_type = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_safe = db.Column(db.Boolean, default=True)
    risk_level = db.Column(db.String(20), default='low')  # low, medium, high, critical
    violations = db.Column(db.JSON)  # Store detected violations
    scan_timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    user = db.relationship('User', backref='file_scans')
    
    def __repr__(self):
        return f'<FileScan {self.filename}: {self.risk_level}>'

class EmailTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    subject = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    template_type = db.Column(db.String(50), default='notification')  # notification, alert, report
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<EmailTemplate {self.name}>'

class NotificationRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    trigger_condition = db.Column(db.String(50), nullable=False)  # violation, incident, threshold
    severity_threshold = db.Column(db.String(20), default='medium')
    notification_method = db.Column(db.String(50), default='email')  # email, webhook, sms
    recipients = db.Column(db.JSON)  # List of recipient emails/numbers
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<NotificationRule {self.name}>'

class BackupLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    backup_type = db.Column(db.String(50), nullable=False)  # full, incremental, manual
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer)
    status = db.Column(db.String(20), default='pending')  # pending, completed, failed
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    completed_at = db.Column(db.DateTime)
    error_message = db.Column(db.Text)
    
    creator = db.relationship('User', backref='backups')
    
    def __repr__(self):
        return f'<BackupLog {self.backup_type}: {self.status}>'
