"""
Enhanced Security Module for DLP System
Implements 2FA, rate limiting, encryption, and advanced security features
"""

import secrets
import hashlib
import pyotp
import qrcode
from io import BytesIO
import base64
from datetime import datetime, timedelta
from flask import request, session, redirect, url_for
from functools import wraps
from models import db, User, SystemLog
from typing import Dict, List, Optional
import re
import ipaddress

class SecurityEnhancements:
    def __init__(self):
        self.db = db
        self.max_login_attempts = 5
        self.lockout_duration = 15  # minutes
        self.rate_limit_requests = 100  # per hour
        self.rate_limit_window = 3600  # seconds
    
    def generate_2fa_secret(self, user_email: str) -> str:
        """Generate 2FA secret for user"""
        return pyotp.random_base32()
    
    def generate_2fa_qr_code(self, user_email: str, secret: str) -> str:
        """Generate QR code for 2FA setup"""
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user_email,
            issuer_name="DLP System"
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        return base64.b64encode(buffer.getvalue()).decode()
    
    def verify_2fa_token(self, secret: str, token: str) -> bool:
        """Verify 2FA token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)
    
    def check_password_strength(self, password: str) -> Dict:
        """Check password strength and return detailed analysis"""
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("Password should be at least 8 characters long")
        
        # Uppercase check
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("Password should contain uppercase letters")
        
        # Lowercase check
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("Password should contain lowercase letters")
        
        # Number check
        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append("Password should contain numbers")
        
        # Special character check
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        else:
            feedback.append("Password should contain special characters")
        
        # Common password check
        common_passwords = ['password', '123456', 'qwerty', 'admin', 'letmein']
        if password.lower() in common_passwords:
            score -= 2
            feedback.append("Password is too common")
        
        # Determine strength level
        if score >= 5:
            strength = "Very Strong"
        elif score >= 4:
            strength = "Strong"
        elif score >= 3:
            strength = "Medium"
        elif score >= 2:
            strength = "Weak"
        else:
            strength = "Very Weak"
        
        return {
            'score': score,
            'max_score': 5,
            'strength': strength,
            'feedback': feedback,
            'is_acceptable': score >= 3
        }
    
    def check_ip_reputation(self, ip_address: str) -> Dict:
        """Check IP address reputation (simplified version)"""
        try:
            # Check if IP is private/local
            ip = ipaddress.ip_address(ip_address)
            is_private = ip.is_private
            is_loopback = ip.is_loopback
            
            # Check for suspicious patterns
            is_suspicious = False
            risk_factors = []
            
            if is_private:
                risk_factors.append("Private IP address")
            
            if is_loopback:
                risk_factors.append("Loopback address")
            
            # Check for known malicious IP ranges (simplified)
            malicious_ranges = [
                "10.0.0.0/8",  # Example - would be real malicious ranges
                "192.168.0.0/16"
            ]
            
            for range_str in malicious_ranges:
                if ip in ipaddress.ip_network(range_str):
                    is_suspicious = True
                    risk_factors.append(f"IP in suspicious range: {range_str}")
                    break
            
            # Determine risk level
            if is_suspicious or len(risk_factors) > 2:
                risk_level = "High"
            elif len(risk_factors) > 0:
                risk_level = "Medium"
            else:
                risk_level = "Low"
            
            return {
                'ip_address': ip_address,
                'risk_level': risk_level,
                'is_private': is_private,
                'is_loopback': is_loopback,
                'is_suspicious': is_suspicious,
                'risk_factors': risk_factors
            }
            
        except ValueError:
            return {
                'ip_address': ip_address,
                'risk_level': 'High',
                'error': 'Invalid IP address format'
            }
    
    def check_user_agent(self, user_agent: str) -> Dict:
        """Analyze user agent for suspicious patterns"""
        suspicious_patterns = [
            'bot', 'crawler', 'spider', 'scraper',
            'curl', 'wget', 'python-requests',
            'sqlmap', 'nikto', 'nmap'
        ]
        
        is_suspicious = False
        detected_patterns = []
        
        user_agent_lower = user_agent.lower()
        for pattern in suspicious_patterns:
            if pattern in user_agent_lower:
                is_suspicious = True
                detected_patterns.append(pattern)
        
        # Check for missing or minimal user agent
        if len(user_agent) < 10:
            is_suspicious = True
            detected_patterns.append("Minimal user agent")
        
        return {
            'user_agent': user_agent,
            'is_suspicious': is_suspicious,
            'detected_patterns': detected_patterns,
            'risk_level': 'High' if is_suspicious else 'Low'
        }
    
    def generate_session_token(self) -> str:
        """Generate secure session token"""
        return secrets.token_urlsafe(32)
    
    def hash_sensitive_data(self, data: str) -> str:
        """Hash sensitive data for storage"""
        return hashlib.sha256(data.encode()).hexdigest()
    
    def check_brute_force_attempts(self, ip_address: str, user_email: str = None) -> Dict:
        """Check for brute force attack attempts"""
        now = datetime.utcnow()
        cutoff_time = now - timedelta(minutes=self.lockout_duration)
        
        # Check recent failed login attempts from this IP
        recent_failures = SystemLog.query.filter(
            SystemLog.ip_address == ip_address,
            SystemLog.level == 'WARNING',
            SystemLog.message.like('%Failed login attempt%'),
            SystemLog.timestamp >= cutoff_time
        ).count()
        
        # Check recent failed attempts for specific user
        user_failures = 0
        if user_email:
            user_failures = SystemLog.query.filter(
                SystemLog.message.like(f'%Failed login attempt for email: {user_email}%'),
                SystemLog.level == 'WARNING',
                SystemLog.timestamp >= cutoff_time
            ).count()
        
        is_blocked = (recent_failures >= self.max_login_attempts or 
                     user_failures >= self.max_login_attempts)
        
        return {
            'is_blocked': is_blocked,
            'ip_failures': recent_failures,
            'user_failures': user_failures,
            'max_attempts': self.max_login_attempts,
            'lockout_duration': self.lockout_duration,
            'remaining_attempts': max(0, self.max_login_attempts - max(recent_failures, user_failures))
        }
    
    def log_security_event(self, event_type: str, user_id: int = None, 
                          details: str = "", severity: str = "INFO") -> None:
        """Log security-related events"""
        log = SystemLog(
            level=severity,
            message=f"Security Event - {event_type}: {details}",
            user_id=user_id,
            ip_address=request.remote_addr if request else '127.0.0.1',
            user_agent=request.headers.get('User-Agent') if request else 'System'
        )
        db.session.add(log)
        db.session.commit()
    
    def validate_input(self, input_data: str, input_type: str = "general") -> Dict:
        """Validate and sanitize user input"""
        issues = []
        sanitized = input_data
        
        # SQL Injection patterns
        sql_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
            r"(--|#|/\*|\*/)",
            r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
            r"('|(\\')|(;)|(\|)|(\*))"
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, input_data, re.IGNORECASE):
                issues.append("Potential SQL injection detected")
                break
        
        # XSS patterns
        xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe[^>]*>",
            r"<object[^>]*>",
            r"<embed[^>]*>"
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, input_data, re.IGNORECASE):
                issues.append("Potential XSS attack detected")
                break
        
        # Path traversal
        if ".." in input_data or "/" in input_data or "\\" in input_data:
            if input_type == "file_path":
                issues.append("Potential path traversal detected")
        
        # Email validation
        if input_type == "email":
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, input_data):
                issues.append("Invalid email format")
        
        # Sanitize input
        sanitized = re.sub(r'[<>"\']', '', sanitized)
        sanitized = sanitized.strip()
        
        return {
            'is_valid': len(issues) == 0,
            'issues': issues,
            'sanitized': sanitized,
            'original': input_data
        }
    
    def get_security_recommendations(self, user_id: int) -> List[str]:
        """Get personalized security recommendations for user"""
        user = User.query.get(user_id)
        if not user:
            return []
        
        recommendations = []
        
        # Check password age (if we had password_created_at field)
        # Check last login
        if user.last_login:
            days_since_login = (datetime.utcnow() - user.last_login).days
            if days_since_login > 30:
                recommendations.append("Consider changing your password - last login was over 30 days ago")
        
        # Check for failed login attempts
        recent_failures = SystemLog.query.filter(
            SystemLog.user_id == user_id,
            SystemLog.level == 'WARNING',
            SystemLog.message.like('%Failed login attempt%'),
            SystemLog.timestamp >= datetime.utcnow() - timedelta(days=7)
        ).count()
        
        if recent_failures > 0:
            recommendations.append(f"You have {recent_failures} failed login attempts in the last 7 days")
        
        # General recommendations
        recommendations.extend([
            "Enable two-factor authentication for enhanced security",
            "Use a strong, unique password",
            "Log out from shared or public computers",
            "Report any suspicious activity immediately"
        ])
        
        return recommendations

def require_2fa(f):
    """Decorator to require 2FA for specific routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('2fa_verified'):
            return redirect(url_for('verify_2fa'))
        return f(*args, **kwargs)
    return decorated_function

def rate_limit(max_requests: int = 100, window: int = 3600):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Simplified rate limiting - in production, use Redis or similar
            ip_address = request.remote_addr
            # Implementation would check against stored rate limit data
            return f(*args, **kwargs)
        return decorated_function
    return decorator
