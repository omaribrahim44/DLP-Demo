# dlp/dlp_engine.py
import re
import json
from datetime import datetime
from typing import List, Dict, Tuple, Optional

class DLPPolicyEngine:
    def __init__(self, db_session=None):
        self.db_session = db_session
        self.default_policies = self._load_default_policies()
    
    def _load_default_policies(self) -> List[Dict]:
        """Load default DLP policies"""
        return [
            {
                "name": "Credit Card Detection",
                "pattern": r"\b(?:\d[ -]*?){13,19}\b",
                "category": "Financial Data",
                "severity": "high",
                "description": "Detects credit card numbers"
            },
            {
                "name": "SSN Detection",
                "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
                "category": "Personal Data",
                "severity": "critical",
                "description": "Detects Social Security Numbers"
            },
            {
                "name": "Password Detection",
                "pattern": r"(password\s*[=:]\s*\S+|pass\s*[=:]\s*\S+|pwd\s*[=:]\s*\S+)",
                "category": "Credentials",
                "severity": "high",
                "description": "Detects password patterns"
            },
            {
                "name": "AWS Key Detection",
                "pattern": r"AKIA[0-9A-Z]{16}",
                "category": "API Keys",
                "severity": "critical",
                "description": "Detects AWS access keys"
            },
            {
                "name": "JWT Token Detection",
                "pattern": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9._-]{10,}\.[a-zA-Z0-9._-]{10,}",
                "category": "Tokens",
                "severity": "high",
                "description": "Detects JWT tokens"
            },
            {
                "name": "IBAN Detection",
                "pattern": r"[A-Z]{2}[0-9]{2}[A-Z0-9]{1,30}",
                "category": "Financial Data",
                "severity": "high",
                "description": "Detects IBAN numbers"
            },
            {
                "name": "Phone Number Detection",
                "pattern": r"(\+?\d{1,3}[-.\s]?)?(\(?\d{2,3}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{4}",
                "category": "Personal Data",
                "severity": "medium",
                "description": "Detects phone numbers"
            },
            {
                "name": "Confidential Keywords",
                "pattern": r"\b(confidential|secret|classified|internal\s+only|proprietary|restricted)\b",
                "category": "Sensitive Keywords",
                "severity": "medium",
                "description": "Detects confidential keywords"
            },
            {
                "name": "API Key Patterns",
                "pattern": r"(api[_-]?key|apikey|access[_-]?key|secret[_-]?key)\s*[=:]\s*[\w\-\.]+",
                "category": "API Keys",
                "severity": "critical",
                "description": "Detects API key patterns"
            },
            {
                "name": "Database Connection Strings",
                "pattern": r"(mongodb|mysql|postgresql|sqlserver)://[^\s]+",
                "category": "Database Credentials",
                "severity": "critical",
                "description": "Detects database connection strings"
            }
        ]
    
    def apply_policies(self, sender: str, recipient: str, content: str, subject: str = "") -> Tuple[bool, str, List[Dict]]:
        """
        Apply DLP policies to email content.
        Returns (allowed: bool, message: str, violations: List[Dict])
        """
        violations = []
        full_content = f"{subject} {content}".lower()
        
        # Get active policies from database if available, otherwise use defaults
        policies = self._get_active_policies()
        
        for policy in policies:
            try:
                if re.search(policy['pattern'], full_content, re.IGNORECASE):
                    violation = {
                        'policy_name': policy['name'],
                        'category': policy['category'],
                        'severity': policy['severity'],
                        'description': policy['description'],
                        'pattern': policy['pattern']
                    }
                    violations.append(violation)
            except re.error:
                # Skip invalid regex patterns
                continue
        
        # Check for external recipient policies
        if self._is_external_recipient(recipient):
            external_violations = self._check_external_policies(content, subject)
            violations.extend(external_violations)
        
        if violations:
            # Determine if any violations are critical enough to block
            critical_violations = [v for v in violations if v['severity'] in ['critical', 'high']]
            if critical_violations:
                return False, f"Message blocked due to {len(violations)} policy violation(s)", violations
            else:
                # Medium/low severity violations might be warnings
                return True, f"Message allowed with {len(violations)} policy warning(s)", violations
        
        return True, "Message delivered successfully", []
    
    def _get_active_policies(self) -> List[Dict]:
        """Get active policies from database or return defaults"""
        if self.db_session:
            try:
                from models import DLPPolicy
                db_policies = self.db_session.query(DLPPolicy).filter_by(is_active=True).all()
                return [
                    {
                        'name': p.name,
                        'pattern': p.pattern,
                        'category': p.category,
                        'severity': p.severity,
                        'description': p.description
                    }
                    for p in db_policies
                ]
            except:
                pass
        
        return self.default_policies
    
    def _is_external_recipient(self, recipient: str) -> bool:
        """Check if recipient is external"""
        internal_domains = ["example.com", "company.com", "internal.org"]
        return not any(recipient.endswith(domain) for domain in internal_domains)
    
    def _check_external_policies(self, content: str, subject: str) -> List[Dict]:
        """Check policies specific to external recipients"""
        violations = []
        full_content = f"{subject} {content}".lower()
        
        # Block emails with internal email addresses to external recipients
        if re.search(r"[a-zA-Z0-9_.+-]+@(example\.com|company\.com|internal\.org)", full_content):
            violations.append({
                'policy_name': 'External Email Sharing',
                'category': 'Data Leakage',
                'severity': 'high',
                'description': 'Internal email addresses shared with external recipient',
                'pattern': 'external_email_sharing'
            })
        
        # Block attachments to external recipients (if mentioned)
        if "[attachment]" in full_content or "attached" in full_content:
            violations.append({
                'policy_name': 'External Attachment',
                'category': 'Data Leakage',
                'severity': 'medium',
                'description': 'Attachments not allowed to external recipients',
                'pattern': 'external_attachment'
            })
        
        return violations

# Backward compatibility function
def apply_policies(sender: str, recipient: str, content: str) -> Tuple[bool, str, str]:
    """
    Legacy function for backward compatibility.
    Returns (allowed: bool, message: str, category: str)
    """
    engine = DLPPolicyEngine()
    allowed, message, violations = engine.apply_policies(sender, recipient, content)
    
    if violations:
        # Return the highest severity category
        severities = ['low', 'medium', 'high', 'critical']
        highest_severity = max(violations, key=lambda v: severities.index(v['severity']))
        category = highest_severity['category']
    else:
        category = "None"
    
    return allowed, message, category
