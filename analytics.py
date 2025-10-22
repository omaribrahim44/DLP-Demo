"""
Advanced Analytics Module for DLP System
Provides comprehensive analytics, reporting, and insights
"""

from datetime import datetime, timedelta
from sqlalchemy import func, and_, or_
from models import db, EmailLog, User, SecurityIncident, SystemLog, DLPPolicy
from typing import Dict, List, Tuple
import json

class DLPAnalytics:
    def __init__(self):
        self.db = db
    
    def get_dashboard_metrics(self) -> Dict:
        """Get comprehensive dashboard metrics"""
        now = datetime.utcnow()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)
        last_30d = now - timedelta(days=30)
        
        return {
            'total_emails': EmailLog.query.count(),
            'blocked_emails': EmailLog.query.filter_by(is_blocked=True).count(),
            'total_users': User.query.count(),
            'active_users': User.query.filter_by(is_active=True).count(),
            'total_incidents': SecurityIncident.query.count(),
            'open_incidents': SecurityIncident.query.filter_by(status='open').count(),
            'active_policies': DLPPolicy.query.filter_by(is_active=True).count(),
            
            # Time-based metrics
            'emails_24h': EmailLog.query.filter(EmailLog.timestamp >= last_24h).count(),
            'blocked_24h': EmailLog.query.filter(
                and_(EmailLog.timestamp >= last_24h, EmailLog.is_blocked == True)
            ).count(),
            'emails_7d': EmailLog.query.filter(EmailLog.timestamp >= last_7d).count(),
            'blocked_7d': EmailLog.query.filter(
                and_(EmailLog.timestamp >= last_7d, EmailLog.is_blocked == True)
            ).count(),
            'emails_30d': EmailLog.query.filter(EmailLog.timestamp >= last_30d).count(),
            'blocked_30d': EmailLog.query.filter(
                and_(EmailLog.timestamp >= last_30d, EmailLog.is_blocked == True)
            ).count(),
        }
    
    def get_violation_trends(self, days: int = 30) -> List[Dict]:
        """Get violation trends over time"""
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # Get daily violation counts
        daily_violations = db.session.query(
            func.date(EmailLog.timestamp).label('date'),
            func.count(EmailLog.id).label('count')
        ).filter(
            and_(
                EmailLog.timestamp >= start_date,
                EmailLog.timestamp <= end_date,
                EmailLog.is_blocked == True
            )
        ).group_by(func.date(EmailLog.timestamp)).all()
        
        return [{'date': str(v.date), 'count': v.count} for v in daily_violations]
    
    def get_top_violators(self, limit: int = 10) -> List[Dict]:
        """Get users with most violations"""
        violators = db.session.query(
            User.name,
            User.email,
            func.count(EmailLog.id).label('violation_count')
        ).join(EmailLog, User.id == EmailLog.sender_id).filter(
            EmailLog.is_blocked == True
        ).group_by(User.id, User.name, User.email).order_by(
            func.count(EmailLog.id).desc()
        ).limit(limit).all()
        
        return [{
            'name': v.name,
            'email': v.email,
            'violations': v.violation_count
        } for v in violators]
    
    def get_policy_effectiveness(self) -> List[Dict]:
        """Get policy effectiveness metrics"""
        policies = DLPPolicy.query.filter_by(is_active=True).all()
        effectiveness = []
        
        for policy in policies:
            # Count violations for this policy
            violations = 0
            for email in EmailLog.query.filter_by(is_blocked=True).all():
                if email.policy_violations:
                    for violation in email.policy_violations:
                        if violation.get('policy_name') == policy.name:
                            violations += 1
                            break
            
            effectiveness.append({
                'policy_name': policy.name,
                'category': policy.category,
                'severity': policy.severity,
                'violations': violations,
                'effectiveness': 'High' if violations > 10 else 'Medium' if violations > 5 else 'Low'
            })
        
        return sorted(effectiveness, key=lambda x: x['violations'], reverse=True)
    
    def get_risk_heatmap(self) -> Dict:
        """Generate risk heatmap data"""
        # Get violations by hour of day
        hourly_violations = db.session.query(
            func.extract('hour', EmailLog.timestamp).label('hour'),
            func.count(EmailLog.id).label('count')
        ).filter(EmailLog.is_blocked == True).group_by(
            func.extract('hour', EmailLog.timestamp)
        ).all()
        
        # Get violations by day of week
        daily_violations = db.session.query(
            func.extract('dow', EmailLog.timestamp).label('day'),
            func.count(EmailLog.id).label('count')
        ).filter(EmailLog.is_blocked == True).group_by(
            func.extract('dow', EmailLog.timestamp)
        ).all()
        
        return {
            'hourly': [{'hour': int(v.hour), 'count': v.count} for v in hourly_violations],
            'daily': [{'day': int(v.day), 'count': v.count} for v in daily_violations]
        }
    
    def get_geographic_risks(self) -> List[Dict]:
        """Get geographic risk analysis (based on IP addresses)"""
        # This is a simplified version - in production, you'd use IP geolocation
        ip_stats = db.session.query(
            SystemLog.ip_address,
            func.count(SystemLog.id).label('count')
        ).filter(
            and_(
                SystemLog.ip_address.isnot(None),
                SystemLog.ip_address != '127.0.0.1'
            )
        ).group_by(SystemLog.ip_address).all()
        
        return [{
            'ip': ip.ip_address,
            'requests': ip.count,
            'risk_level': 'High' if ip.count > 100 else 'Medium' if ip.count > 50 else 'Low'
        } for ip in ip_stats]
    
    def get_compliance_report(self) -> Dict:
        """Generate compliance report"""
        total_emails = EmailLog.query.count()
        blocked_emails = EmailLog.query.filter_by(is_blocked=True).count()
        
        # Calculate compliance metrics
        compliance_rate = ((total_emails - blocked_emails) / total_emails * 100) if total_emails > 0 else 100
        
        # Get policy coverage
        active_policies = DLPPolicy.query.filter_by(is_active=True).count()
        total_policies = DLPPolicy.query.count()
        
        return {
            'compliance_rate': round(compliance_rate, 2),
            'total_emails_scanned': total_emails,
            'emails_blocked': blocked_emails,
            'emails_allowed': total_emails - blocked_emails,
            'policy_coverage': round((active_policies / total_policies * 100) if total_policies > 0 else 0, 2),
            'active_policies': active_policies,
            'total_policies': total_policies,
            'last_updated': datetime.utcnow().isoformat()
        }
    
    def get_threat_intelligence(self) -> Dict:
        """Get threat intelligence summary"""
        # Get recent high-severity incidents
        recent_incidents = SecurityIncident.query.filter(
            SecurityIncident.severity.in_(['critical', 'high'])
        ).order_by(SecurityIncident.created_at.desc()).limit(10).all()
        
        # Get trending violation patterns
        violation_patterns = {}
        for email in EmailLog.query.filter_by(is_blocked=True).limit(100).all():
            if email.policy_violations:
                for violation in email.policy_violations:
                    category = violation.get('category', 'Unknown')
                    violation_patterns[category] = violation_patterns.get(category, 0) + 1
        
        return {
            'recent_incidents': [{
                'type': incident.incident_type,
                'severity': incident.severity,
                'description': incident.description,
                'timestamp': incident.created_at.isoformat()
            } for incident in recent_incidents],
            'trending_violations': violation_patterns,
            'threat_level': 'High' if len(recent_incidents) > 5 else 'Medium' if len(recent_incidents) > 2 else 'Low'
        }
