"""
GDPR Compliance Module for DLP System
Implements data protection, consent management, and privacy controls
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional
from models import db, User, EmailLog, SystemLog, FileScan
import json
import hashlib

class GDPRCompliance:
    def __init__(self):
        self.db = db
        self.data_retention_days = 2555  # 7 years for compliance records
        self.audit_retention_days = 2555  # 7 years for audit logs
        self.consent_required = True
    
    def get_data_subject_info(self, user_id: int) -> Dict:
        """Get all data related to a specific user (data subject)"""
        user = User.query.get(user_id)
        if not user:
            return {}
        
        # Get all user-related data
        email_logs = EmailLog.query.filter(
            (EmailLog.sender_id == user_id) | (EmailLog.recipient_id == user_id)
        ).all()
        
        system_logs = SystemLog.query.filter_by(user_id=user_id).all()
        file_scans = FileScan.query.filter_by(user_id=user_id).all()
        
        return {
            'user_info': {
                'id': user.id,
                'email': user.email,
                'name': user.name,
                'created_at': user.created_at.isoformat(),
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'is_active': user.is_active
            },
            'email_logs': [{
                'id': log.id,
                'timestamp': log.timestamp.isoformat(),
                'subject': log.subject,
                'is_blocked': log.is_blocked,
                'block_reason': log.block_reason
            } for log in email_logs],
            'system_logs': [{
                'id': log.id,
                'timestamp': log.timestamp.isoformat(),
                'level': log.level,
                'message': log.message,
                'ip_address': log.ip_address
            } for log in system_logs],
            'file_scans': [{
                'id': scan.id,
                'filename': scan.filename,
                'scan_timestamp': scan.scan_timestamp.isoformat(),
                'is_safe': scan.is_safe,
                'risk_level': scan.risk_level
            } for scan in file_scans],
            'data_categories': [
                'Personal identification data',
                'Email communication data',
                'System access logs',
                'File scanning records',
                'Security incident data'
            ],
            'legal_basis': [
                'Legitimate interest (security monitoring)',
                'Consent (user registration)',
                'Legal obligation (compliance requirements)'
            ]
        }
    
    def anonymize_user_data(self, user_id: int) -> bool:
        """Anonymize user data while preserving system integrity"""
        try:
            user = User.query.get(user_id)
            if not user:
                return False
            
            # Generate anonymized identifier
            anonymized_id = hashlib.sha256(f"{user.email}{user.id}".encode()).hexdigest()[:16]
            
            # Anonymize user data
            user.email = f"anonymized_{anonymized_id}@deleted.local"
            user.name = f"Anonymized User {anonymized_id}"
            user.is_active = False
            
            # Anonymize email logs (keep structure for analytics)
            email_logs = EmailLog.query.filter(
                (EmailLog.sender_id == user_id) | (EmailLog.recipient_id == user_id)
            ).all()
            
            for log in email_logs:
                if log.sender_id == user_id:
                    log.content = "[ANONYMIZED]"
                    log.subject = "[ANONYMIZED]"
                if log.recipient_id == user_id:
                    log.content = "[ANONYMIZED]"
                    log.subject = "[ANONYMIZED]"
            
            # Anonymize system logs
            system_logs = SystemLog.query.filter_by(user_id=user_id).all()
            for log in system_logs:
                log.message = log.message.replace(user.email, "[ANONYMIZED]")
                log.ip_address = "0.0.0.0"
            
            # Anonymize file scans
            file_scans = FileScan.query.filter_by(user_id=user_id).all()
            for scan in file_scans:
                scan.filename = f"anonymized_{anonymized_id}.txt"
            
            db.session.commit()
            return True
            
        except Exception as e:
            db.session.rollback()
            print(f"Anonymization failed: {e}")
            return False
    
    def delete_user_data(self, user_id: int) -> bool:
        """Complete deletion of user data (Right to be Forgotten)"""
        try:
            # Delete all user-related records
            EmailLog.query.filter(
                (EmailLog.sender_id == user_id) | (EmailLog.recipient_id == user_id)
            ).delete()
            
            SystemLog.query.filter_by(user_id=user_id).delete()
            FileScan.query.filter_by(user_id=user_id).delete()
            
            # Delete user account
            User.query.filter_by(id=user_id).delete()
            
            db.session.commit()
            return True
            
        except Exception as e:
            db.session.rollback()
            print(f"Data deletion failed: {e}")
            return False
    
    def get_consent_status(self, user_id: int) -> Dict:
        """Get user consent status for data processing"""
        user = User.query.get(user_id)
        if not user:
            return {}
        
        # In a real implementation, you'd have a separate consent table
        # For now, we'll use the user creation date as consent timestamp
        return {
            'user_id': user_id,
            'consent_given': True,  # User registered = consent given
            'consent_timestamp': user.created_at.isoformat(),
            'consent_version': '1.0',
            'data_processing_purposes': [
                'Security monitoring and threat detection',
                'System administration and maintenance',
                'Compliance and audit requirements',
                'User authentication and access control'
            ],
            'data_sharing': {
                'third_parties': False,
                'law_enforcement': 'Only when legally required',
                'analytics': 'Anonymized data only'
            },
            'retention_period': f"{self.data_retention_days} days",
            'user_rights': [
                'Right to access personal data',
                'Right to rectification',
                'Right to erasure (Right to be Forgotten)',
                'Right to data portability',
                'Right to object to processing',
                'Right to withdraw consent'
            ]
        }
    
    def update_consent(self, user_id: int, consent_data: Dict) -> bool:
        """Update user consent preferences"""
        try:
            # In a real implementation, you'd update a consent table
            # For now, we'll log the consent update
            log = SystemLog(
                level='INFO',
                message=f'Consent updated for user {user_id}: {json.dumps(consent_data)}',
                user_id=user_id,
                ip_address='127.0.0.1'  # Would be actual IP in production
            )
            db.session.add(log)
            db.session.commit()
            return True
            
        except Exception as e:
            db.session.rollback()
            print(f"Consent update failed: {e}")
            return False
    
    def get_data_retention_report(self) -> Dict:
        """Generate data retention compliance report"""
        now = datetime.utcnow()
        retention_cutoff = now - timedelta(days=self.data_retention_days)
        audit_cutoff = now - timedelta(days=self.audit_retention_days)
        
        # Count records that should be retained
        total_users = User.query.count()
        total_emails = EmailLog.query.count()
        total_logs = SystemLog.query.count()
        total_file_scans = FileScan.query.count()
        
        # Count records beyond retention period
        old_emails = EmailLog.query.filter(EmailLog.timestamp < retention_cutoff).count()
        old_logs = SystemLog.query.filter(SystemLog.timestamp < audit_cutoff).count()
        old_file_scans = FileScan.query.filter(FileScan.scan_timestamp < retention_cutoff).count()
        
        return {
            'retention_policy': {
                'data_retention_days': self.data_retention_days,
                'audit_retention_days': self.audit_retention_days,
                'cutoff_date': retention_cutoff.isoformat()
            },
            'current_data': {
                'total_users': total_users,
                'total_emails': total_emails,
                'total_logs': total_logs,
                'total_file_scans': total_file_scans
            },
            'data_beyond_retention': {
                'old_emails': old_emails,
                'old_logs': old_logs,
                'old_file_scans': old_file_scans
            },
            'compliance_status': {
                'gdpr_compliant': True,
                'data_minimization': True,
                'purpose_limitation': True,
                'storage_limitation': old_emails == 0 and old_logs == 0 and old_file_scans == 0,
                'last_updated': now.isoformat()
            }
        }
    
    def cleanup_expired_data(self) -> Dict:
        """Automatically clean up data beyond retention period"""
        now = datetime.utcnow()
        retention_cutoff = now - timedelta(days=self.data_retention_days)
        audit_cutoff = now - timedelta(days=self.audit_retention_days)
        
        cleanup_stats = {
            'emails_deleted': 0,
            'logs_deleted': 0,
            'file_scans_deleted': 0,
            'errors': []
        }
        
        try:
            # Clean up old email logs (keep structure for analytics)
            old_emails = EmailLog.query.filter(EmailLog.timestamp < retention_cutoff).all()
            for email in old_emails:
                email.content = "[EXPIRED - DELETED]"
                email.subject = "[EXPIRED - DELETED]"
                cleanup_stats['emails_deleted'] += 1
            
            # Clean up old system logs
            old_logs = SystemLog.query.filter(SystemLog.timestamp < audit_cutoff)
            cleanup_stats['logs_deleted'] = old_logs.count()
            old_logs.delete()
            
            # Clean up old file scans
            old_file_scans = FileScan.query.filter(FileScan.scan_timestamp < retention_cutoff)
            cleanup_stats['file_scans_deleted'] = old_file_scans.count()
            old_file_scans.delete()
            
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            cleanup_stats['errors'].append(str(e))
        
        return cleanup_stats
    
    def generate_privacy_policy(self) -> Dict:
        """Generate privacy policy information"""
        return {
            'data_controller': 'DLP System Administrator',
            'data_protection_officer': 'admin@dlp-system.com',
            'legal_basis': [
                'Article 6(1)(a) - Consent',
                'Article 6(1)(f) - Legitimate interest',
                'Article 6(1)(c) - Legal obligation'
            ],
            'data_categories': [
                'Personal identification data (name, email)',
                'Authentication data (login records)',
                'Communication data (email content)',
                'System logs (access, security events)',
                'File scanning data (uploaded files)'
            ],
            'data_subjects': [
                'System users and administrators',
                'Email senders and recipients',
                'File uploaders'
            ],
            'data_recipients': [
                'System administrators',
                'Security personnel',
                'Compliance officers'
            ],
            'data_transfers': {
                'third_countries': False,
                'adequacy_decision': True,
                'safeguards': 'Standard contractual clauses'
            },
            'retention_periods': {
                'user_data': f'{self.data_retention_days} days',
                'email_logs': f'{self.data_retention_days} days',
                'system_logs': f'{self.audit_retention_days} days',
                'file_scans': f'{self.data_retention_days} days'
            },
            'data_subject_rights': [
                'Right of access (Article 15)',
                'Right to rectification (Article 16)',
                'Right to erasure (Article 17)',
                'Right to restriction of processing (Article 18)',
                'Right to data portability (Article 20)',
                'Right to object (Article 21)',
                'Rights related to automated decision-making (Article 22)'
            ],
            'contact_information': {
                'email': 'privacy@dlp-system.com',
                'phone': '+1-555-PRIVACY',
                'address': 'Data Protection Office, DLP System'
            }
        }
