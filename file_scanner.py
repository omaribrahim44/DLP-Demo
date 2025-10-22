"""
Advanced File Scanning Module for DLP System
Scans uploaded files for sensitive data and policy violations
"""

import os
import re
import hashlib
from datetime import datetime
from typing import List, Dict, Tuple, Optional
from werkzeug.utils import secure_filename
from models import db, FileScan, User
import mimetypes

class FileScanner:
    def __init__(self, upload_folder: str = 'uploads'):
        self.upload_folder = upload_folder
        self.allowed_extensions = {
            'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 
            'csv', 'json', 'xml', 'log', 'sql', 'py', 'js', 'html', 'css'
        }
        self.max_file_size = 16 * 1024 * 1024  # 16MB
        
        # Ensure upload directory exists
        os.makedirs(upload_folder, exist_ok=True)
    
    def allowed_file(self, filename: str) -> bool:
        """Check if file extension is allowed"""
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in self.allowed_extensions
    
    def scan_file_content(self, content: str, filename: str) -> Tuple[bool, List[Dict], str]:
        """
        Scan file content for sensitive data
        Returns (is_safe, violations, risk_level)
        """
        violations = []
        risk_score = 0
        
        # Credit card patterns
        cc_patterns = [
            r'\b(?:\d[ -]*?){13,19}\b',  # General credit card
            r'\b4[0-9]{12}(?:[0-9]{3})?\b',  # Visa
            r'\b5[1-5][0-9]{14}\b',  # MasterCard
            r'\b3[47][0-9]{13}\b',  # American Express
        ]
        
        for pattern in cc_patterns:
            if re.search(pattern, content):
                violations.append({
                    'type': 'Credit Card',
                    'severity': 'critical',
                    'pattern': pattern,
                    'description': 'Credit card number detected'
                })
                risk_score += 10
        
        # SSN patterns
        ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
        if re.search(ssn_pattern, content):
            violations.append({
                'type': 'SSN',
                'severity': 'critical',
                'pattern': ssn_pattern,
                'description': 'Social Security Number detected'
            })
            risk_score += 10
        
        # API Keys and tokens
        api_patterns = [
            r'AKIA[0-9A-Z]{16}',  # AWS Access Key
            r'sk-[a-zA-Z0-9]{48}',  # OpenAI API Key
            r'[a-zA-Z0-9]{32}',  # Generic API key
            r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9._-]{10,}\.[a-zA-Z0-9._-]{10,}',  # JWT
        ]
        
        for pattern in api_patterns:
            if re.search(pattern, content):
                violations.append({
                    'type': 'API Key',
                    'severity': 'high',
                    'pattern': pattern,
                    'description': 'API key or token detected'
                })
                risk_score += 8
        
        # Database connection strings
        db_patterns = [
            r'(mongodb|mysql|postgresql|sqlserver)://[^\s]+',
            r'jdbc:[a-zA-Z0-9:/.-]+',
        ]
        
        for pattern in db_patterns:
            if re.search(pattern, content):
                violations.append({
                    'type': 'Database Credentials',
                    'severity': 'critical',
                    'pattern': pattern,
                    'description': 'Database connection string detected'
                })
                risk_score += 10
        
        # Email addresses (potential data leakage)
        email_pattern = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
        emails = re.findall(email_pattern, content)
        if len(emails) > 10:  # Large number of emails might indicate data dump
            violations.append({
                'type': 'Email List',
                'severity': 'medium',
                'pattern': email_pattern,
                'description': f'Large number of email addresses detected ({len(emails)})'
            })
            risk_score += 5
        
        # Sensitive keywords
        sensitive_keywords = [
            'password', 'secret', 'confidential', 'classified', 'proprietary',
            'internal', 'private', 'restricted', 'sensitive', 'personal'
        ]
        
        keyword_count = 0
        for keyword in sensitive_keywords:
            if keyword.lower() in content.lower():
                keyword_count += 1
        
        if keyword_count > 3:
            violations.append({
                'type': 'Sensitive Keywords',
                'severity': 'medium',
                'pattern': 'keyword_detection',
                'description': f'Multiple sensitive keywords detected ({keyword_count})'
            })
            risk_score += 3
        
        # Determine risk level
        if risk_score >= 20:
            risk_level = 'critical'
        elif risk_score >= 15:
            risk_level = 'high'
        elif risk_score >= 10:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        is_safe = len(violations) == 0 or risk_level in ['low', 'medium']
        
        return is_safe, violations, risk_level
    
    def scan_file(self, file, user_id: int, filename: str) -> Dict:
        """Scan uploaded file for sensitive data"""
        if not self.allowed_file(filename):
            return {
                'success': False,
                'error': 'File type not allowed',
                'allowed_types': list(self.allowed_extensions)
            }
        
        # Check file size
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)  # Reset to beginning
        
        if file_size > self.max_file_size:
            return {
                'success': False,
                'error': f'File too large. Maximum size: {self.max_file_size // (1024*1024)}MB'
            }
        
        # Read file content
        try:
            content = file.read().decode('utf-8', errors='ignore')
        except Exception as e:
            return {
                'success': False,
                'error': f'Could not read file: {str(e)}'
            }
        
        # Scan content
        is_safe, violations, risk_level = self.scan_file_content(content, filename)
        
        # Generate file hash
        file.seek(0)
        file_hash = hashlib.sha256(file.read()).hexdigest()
        file.seek(0)
        
        # Save file scan record
        file_scan = FileScan(
            filename=secure_filename(filename),
            file_hash=file_hash,
            file_size=file_size,
            mime_type=mimetypes.guess_type(filename)[0] or 'application/octet-stream',
            user_id=user_id,
            is_safe=is_safe,
            risk_level=risk_level,
            violations=violations,
            scan_timestamp=datetime.utcnow()
        )
        
        db.session.add(file_scan)
        db.session.commit()
        
        return {
            'success': True,
            'file_scan_id': file_scan.id,
            'is_safe': is_safe,
            'risk_level': risk_level,
            'violations': violations,
            'file_size': file_size,
            'file_hash': file_hash
        }
    
    def get_scan_history(self, user_id: Optional[int] = None, limit: int = 50) -> List[Dict]:
        """Get file scan history"""
        query = FileScan.query
        if user_id:
            query = query.filter_by(user_id=user_id)
        
        scans = query.order_by(FileScan.scan_timestamp.desc()).limit(limit).all()
        
        return [{
            'id': scan.id,
            'filename': scan.filename,
            'file_size': scan.file_size,
            'mime_type': scan.mime_type,
            'is_safe': scan.is_safe,
            'risk_level': scan.risk_level,
            'violations_count': len(scan.violations) if scan.violations else 0,
            'scan_timestamp': scan.scan_timestamp.isoformat(),
            'user_name': scan.user.name if scan.user else 'Unknown'
        } for scan in scans]
    
    def get_scan_statistics(self) -> Dict:
        """Get file scan statistics"""
        total_scans = FileScan.query.count()
        safe_files = FileScan.query.filter_by(is_safe=True).count()
        unsafe_files = FileScan.query.filter_by(is_safe=False).count()
        
        # Risk level distribution
        risk_levels = db.session.query(
            FileScan.risk_level,
            func.count(FileScan.id).label('count')
        ).group_by(FileScan.risk_level).all()
        
        return {
            'total_scans': total_scans,
            'safe_files': safe_files,
            'unsafe_files': unsafe_files,
            'safety_rate': round((safe_files / total_scans * 100) if total_scans > 0 else 0, 2),
            'risk_distribution': {r.risk_level: r.count for r in risk_levels}
        }
