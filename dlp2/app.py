import os
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, login_required, current_user
from werkzeug.security import generate_password_hash

# Import our modules
from config import Config
from models import db, User, EmailLog, DLPPolicy, SystemLog, SecurityIncident, FileScan, EmailTemplate, NotificationRule, BackupLog
from dlp.dlp_engine import DLPPolicyEngine
from auth import auth_bp
from analytics import DLPAnalytics
from file_scanner import FileScanner
from gdpr_compliance import GDPRCompliance
from security_enhancements import SecurityEnhancements
from werkzeug.utils import secure_filename
import os
import shutil
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/auth')

# Ensure logs directory exists
os.makedirs("logs", exist_ok=True)

# Configure logging
logging.basicConfig(
    level=getattr(logging, app.config['LOG_LEVEL']),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(app.config['LOG_FILE']),
        logging.StreamHandler()
    ]
)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Initialize modules (will be initialized in app context)
analytics = None
file_scanner = None
gdpr_compliance = None
security_enhancements = None

def get_analytics():
    global analytics
    if analytics is None:
        analytics = DLPAnalytics()
    return analytics

def get_file_scanner():
    global file_scanner
    if file_scanner is None:
        file_scanner = FileScanner()
    return file_scanner

def get_gdpr_compliance():
    global gdpr_compliance
    if gdpr_compliance is None:
        gdpr_compliance = GDPRCompliance()
    return gdpr_compliance

def get_security_enhancements():
    global security_enhancements
    if security_enhancements is None:
        security_enhancements = SecurityEnhancements()
    return security_enhancements

# Initialize database and create default data
def init_db():
    """Initialize database with default data"""
    with app.app_context():
        db.create_all()
        
        # Create admin user if not exists
        admin = User.query.filter_by(email=app.config['ADMIN_EMAIL']).first()
        if not admin:
            admin = User(
                email=app.config['ADMIN_EMAIL'],
                name='System Administrator',
                is_admin=True,
                is_active=True
            )
            admin.set_password(app.config['ADMIN_PASSWORD'])
            db.session.add(admin)
        
        # Create demo users if not exist
        demo_users = [
            ("alice@example.com", "Alice Johnson"),
            ("bob@example.com", "Bob Smith"),
            ("charlie@external.com", "Charlie Brown")
        ]
        
        for email, name in demo_users:
            user = User.query.filter_by(email=email).first()
            if not user:
                user = User(email=email, name=name, is_active=True)
                user.set_password("demo123")  # Default password for demo users
                db.session.add(user)
        
        # Create default DLP policies if not exist
        if DLPPolicy.query.count() == 0:
            engine = DLPPolicyEngine()
            for policy_data in engine.default_policies:
                policy = DLPPolicy(
                    name=policy_data['name'],
                    description=policy_data['description'],
                    pattern=policy_data['pattern'],
                    category=policy_data['category'],
                    severity=policy_data['severity'],
                    is_active=True
                )
                db.session.add(policy)
        
        db.session.commit()
        logging.info("Database initialized successfully")

@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('auth.login'))

@app.route("/dashboard")
@login_required
def dashboard():
    """Main dashboard"""
    # Get recent email logs
    recent_emails = EmailLog.query.order_by(EmailLog.timestamp.desc()).limit(10).all()
    
    # Get statistics
    total_emails = EmailLog.query.count()
    blocked_emails = EmailLog.query.filter_by(is_blocked=True).count()
    total_users = User.query.count()
    
    # Get policy violations by category
    violations_by_category = db.session.query(
        EmailLog.policy_violations
    ).filter(EmailLog.is_blocked == True).all()
    
    category_stats = {}
    for violation_data in violations_by_category:
        if violation_data[0]:  # policy_violations is not None
            violations = violation_data[0] if isinstance(violation_data[0], list) else [violation_data[0]]
            for violation in violations:
                category = violation.get('category', 'Unknown')
                category_stats[category] = category_stats.get(category, 0) + 1
    
    return render_template("dashboard.html", 
                         recent_emails=recent_emails,
                         total_emails=total_emails,
                         blocked_emails=blocked_emails,
                         total_users=total_users,
                         category_stats=category_stats)

@app.route("/send", methods=["GET", "POST"])
@login_required
def send_email():
    if request.method == "POST":
        recipient_email = request.form.get("recipient")
        subject = request.form.get("subject", "")
        content = request.form.get("content")
        
        # Find recipient user
        recipient = User.query.filter_by(email=recipient_email).first()
        if not recipient:
            flash("Recipient not found", "danger")
            return redirect(url_for("send_email"))
        
        # Apply DLP policies
        engine = DLPPolicyEngine(db.session)
        allowed, message, violations = engine.apply_policies(
            current_user.email, recipient_email, content, subject
        )
        
        # Log the email attempt
        email_log = EmailLog(
            sender_id=current_user.id,
            recipient_id=recipient.id,
            content=content,
            subject=subject,
            is_blocked=not allowed,
            block_reason=message if not allowed else None,
            policy_violations=violations
        )
        db.session.add(email_log)
        
        # Create security incident if blocked
        if not allowed and violations:
            for violation in violations:
                if violation['severity'] in ['critical', 'high']:
                    incident = SecurityIncident(
                        incident_type=violation['category'],
                        severity=violation['severity'],
                        description=f"DLP Policy Violation: {violation['policy_name']}",
                        user_id=current_user.id,
                        email_log_id=email_log.id
                    )
                    db.session.add(incident)
        
        # Log system event
        system_log = SystemLog(
            level='WARNING' if not allowed else 'INFO',
            message=f"Email {'blocked' if not allowed else 'sent'} from {current_user.email} to {recipient_email}",
            user_id=current_user.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        db.session.add(system_log)
        
        db.session.commit()
        
        if allowed:
            flash(f"✅ {message}", "success")
        else:
            flash(f"🚨 {message}", "danger")
        
        return redirect(url_for("dashboard"))
    
    # Get all users for recipient selection
    users = User.query.filter(User.id != current_user.id, User.is_active == True).all()
    return render_template("send_email.html", users=users)

@app.route("/incidents")
@login_required
def incidents():
    """View security incidents and blocked emails"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Get blocked emails with pagination
    blocked_emails = EmailLog.query.filter_by(is_blocked=True)\
        .order_by(EmailLog.timestamp.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    # Get security incidents
    security_incidents = SecurityIncident.query\
        .order_by(SecurityIncident.created_at.desc())\
        .limit(10).all()
    
    return render_template("incidents.html", 
                         blocked_emails=blocked_emails,
                         security_incidents=security_incidents)

# ------------------------------
# Admin Dashboard + Features
# ------------------------------
@app.route("/admin")
@login_required
def admin_dashboard():
    """Admin dashboard with comprehensive statistics"""
    if not current_user.is_admin:
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for("dashboard"))
    
    # Get comprehensive statistics
    stats = {
        'total_users': User.query.count(),
        'active_users': User.query.filter_by(is_active=True).count(),
        'total_emails': EmailLog.query.count(),
        'blocked_emails': EmailLog.query.filter_by(is_blocked=True).count(),
        'total_incidents': SecurityIncident.query.count(),
        'open_incidents': SecurityIncident.query.filter_by(status='open').count(),
        'total_policies': DLPPolicy.query.count(),
        'active_policies': DLPPolicy.query.filter_by(is_active=True).count()
    }
    
    # Get recent activity
    recent_emails = EmailLog.query.order_by(EmailLog.timestamp.desc()).limit(10).all()
    recent_incidents = SecurityIncident.query.order_by(SecurityIncident.created_at.desc()).limit(5).all()
    recent_logs = SystemLog.query.order_by(SystemLog.timestamp.desc()).limit(10).all()
    
    # Get policy violation statistics
    violations_by_category = db.session.query(
        EmailLog.policy_violations
    ).filter(EmailLog.is_blocked == True).all()
    
    category_stats = {}
    for violation_data in violations_by_category:
        if violation_data[0]:
            violations = violation_data[0] if isinstance(violation_data[0], list) else [violation_data[0]]
            for violation in violations:
                category = violation.get('category', 'Unknown')
                category_stats[category] = category_stats.get(category, 0) + 1
    
    return render_template("admin_dashboard.html", 
                         stats=stats,
                         recent_emails=recent_emails,
                         recent_incidents=recent_incidents,
                         recent_logs=recent_logs,
                         category_stats=category_stats)

@app.route("/admin/users", methods=["GET", "POST"])
@login_required
def manage_users():
    """Manage users - admin only"""
    if not current_user.is_admin:
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for("dashboard"))
    
    if request.method == "POST":
        action = request.form.get("action")
        email = request.form.get("email")
        name = request.form.get("name")
        password = request.form.get("password")
        
        if action == "add" and email and name:
            if User.query.filter_by(email=email).first():
                flash("User with this email already exists", "danger")
            else:
                user = User(email=email, name=name, is_active=True)
                user.set_password(password or "default123")
                db.session.add(user)
                db.session.commit()
                flash(f"User {name} ({email}) added successfully.", "success")
        
        elif action == "toggle_status" and email:
            user = User.query.filter_by(email=email).first()
            if user:
                user.is_active = not user.is_active
                db.session.commit()
                status = "activated" if user.is_active else "deactivated"
                flash(f"User {email} {status}.", "info")
        
        elif action == "delete" and email:
            user = User.query.filter_by(email=email).first()
            if user and user.id != current_user.id:  # Can't delete self
                db.session.delete(user)
                db.session.commit()
                flash(f"User {email} deleted.", "warning")
            else:
                flash("Cannot delete your own account", "danger")
    
    users = User.query.all()
    return render_template("manage_users.html", users=users)

@app.route("/admin/policies")
@login_required
def manage_policies():
    """Manage DLP policies - admin only"""
    if not current_user.is_admin:
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for("dashboard"))
    
    policies = DLPPolicy.query.all()
    return render_template("manage_policies.html", policies=policies)

@app.route("/admin/logs")
@login_required
def view_logs():
    """View system logs - admin only"""
    if not current_user.is_admin:
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for("dashboard"))
    
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    logs = SystemLog.query.order_by(SystemLog.timestamp.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template("view_logs.html", logs=logs)

@app.route("/api/stats")
@login_required
def api_stats():
    """API endpoint for dashboard statistics"""
    if not current_user.is_admin:
        return jsonify({"error": "Access denied"}), 403
    
    stats = {
        'total_emails': EmailLog.query.count(),
        'blocked_emails': EmailLog.query.filter_by(is_blocked=True).count(),
        'total_users': User.query.count(),
        'active_users': User.query.filter_by(is_active=True).count(),
        'open_incidents': SecurityIncident.query.filter_by(status='open').count()
    }
    
    return jsonify(stats)

# ------------------------------
# Advanced Analytics Routes
# ------------------------------
@app.route("/analytics")
@login_required
def analytics_dashboard():
    """Advanced analytics dashboard"""
    if not current_user.is_admin:
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for("dashboard"))
    
    # Get analytics data
    analytics_engine = get_analytics()
    metrics = analytics_engine.get_dashboard_metrics()
    violation_trends = analytics_engine.get_violation_trends(30)
    top_violators = analytics_engine.get_top_violators(10)
    policy_effectiveness = analytics_engine.get_policy_effectiveness()
    risk_heatmap = analytics_engine.get_risk_heatmap()
    compliance_report = analytics_engine.get_compliance_report()
    threat_intel = analytics_engine.get_threat_intelligence()
    
    return render_template("analytics_dashboard.html",
                         compliance_rate=compliance_report['compliance_rate'],
                         threat_level=threat_intel['threat_level'],
                         active_policies=metrics['active_policies'],
                         open_incidents=metrics['open_incidents'],
                         violation_trends=violation_trends,
                         top_violators=top_violators,
                         policy_effectiveness=policy_effectiveness,
                         risk_distribution=risk_heatmap,
                         recent_incidents=threat_intel['recent_incidents'],
                         trending_violations=threat_intel['trending_violations'])

# ------------------------------
# File Scanner Routes
# ------------------------------
@app.route("/file-scanner", methods=["GET", "POST"])
@login_required
def file_scanner_page():
    """File upload and scanning interface"""
    scan_result = None
    
    if request.method == "POST":
        if 'file' not in request.files:
            flash("No file selected", "danger")
            return redirect(url_for("file_scanner_page"))
        
        file = request.files['file']
        if file.filename == '':
            flash("No file selected", "danger")
            return redirect(url_for("file_scanner_page"))
        
        # Scan the file
        scanner = get_file_scanner()
        result = scanner.scan_file(file, current_user.id, file.filename)
        
        if result['success']:
            scan_result = result
            if result['is_safe']:
                flash("File scanned successfully - No security risks detected", "success")
            else:
                flash(f"Security risks detected: {result['risk_level']} risk level", "warning")
        else:
            flash(f"Scan failed: {result['error']}", "danger")
    
    # Get scan statistics and recent scans
    scanner = get_file_scanner()
    scan_stats = scanner.get_scan_statistics()
    recent_scans = scanner.get_scan_history(current_user.id, 10)
    
    return render_template("file_scanner.html",
                         scan_result=scan_result,
                         scan_stats=scan_stats,
                         recent_scans=recent_scans)

@app.route("/file-scan-history")
@login_required
def file_scan_history():
    """View file scan history"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    scans = FileScan.query.filter_by(user_id=current_user.id)\
        .order_by(FileScan.scan_timestamp.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template("file_scan_history.html", scans=scans)

# ------------------------------
# Backup and Restore Routes
# ------------------------------
@app.route("/admin/backup", methods=["GET", "POST"])
@login_required
def backup_system():
    """System backup functionality"""
    if not current_user.is_admin:
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for("dashboard"))
    
    if request.method == "POST":
        backup_type = request.form.get("backup_type", "manual")
        
        try:
            # Create backup directory
            backup_dir = f"backups/backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            os.makedirs(backup_dir, exist_ok=True)
            
            # Backup database
            db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
            if os.path.exists(db_path):
                shutil.copy2(db_path, f"{backup_dir}/dlp_system.db")
            
            # Backup logs
            if os.path.exists("logs"):
                shutil.copytree("logs", f"{backup_dir}/logs")
            
            # Create backup log entry
            backup_log = BackupLog(
                backup_type=backup_type,
                file_path=backup_dir,
                status='completed',
                created_by=current_user.id,
                completed_at=datetime.utcnow()
            )
            db.session.add(backup_log)
            db.session.commit()
            
            flash(f"Backup completed successfully: {backup_dir}", "success")
        except Exception as e:
            flash(f"Backup failed: {str(e)}", "danger")
    
    # Get backup history
    backups = BackupLog.query.order_by(BackupLog.created_at.desc()).limit(10).all()
    return render_template("backup_restore.html", backups=backups)

# ------------------------------
# API Endpoints
# ------------------------------
@app.route("/api/analytics/trends")
@login_required
def api_analytics_trends():
    """API endpoint for violation trends"""
    if not current_user.is_admin:
        return jsonify({"error": "Access denied"}), 403
    
    days = request.args.get('days', 30, type=int)
    analytics_engine = get_analytics()
    trends = analytics_engine.get_violation_trends(days)
    return jsonify(trends)

@app.route("/api/analytics/violators")
@login_required
def api_analytics_violators():
    """API endpoint for top violators"""
    if not current_user.is_admin:
        return jsonify({"error": "Access denied"}), 403
    
    limit = request.args.get('limit', 10, type=int)
    analytics_engine = get_analytics()
    violators = analytics_engine.get_top_violators(limit)
    return jsonify(violators)

@app.route("/api/compliance")
@login_required
def api_compliance():
    """API endpoint for compliance report"""
    if not current_user.is_admin:
        return jsonify({"error": "Access denied"}), 403
    
    analytics_engine = get_analytics()
    report = analytics_engine.get_compliance_report()
    return jsonify(report)

# ------------------------------
# GDPR Compliance Routes
# ------------------------------
@app.route("/gdpr/data-subject-info")
@login_required
def gdpr_data_subject_info():
    """Get user's personal data information (GDPR Article 15)"""
    gdpr = get_gdpr_compliance()
    data_info = gdpr.get_data_subject_info(current_user.id)
    return render_template("gdpr/data_subject_info.html", data_info=data_info)

@app.route("/gdpr/consent-status")
@login_required
def gdpr_consent_status():
    """Get user consent status"""
    gdpr = get_gdpr_compliance()
    consent_info = gdpr.get_consent_status(current_user.id)
    return render_template("gdpr/consent_status.html", consent_info=consent_info)

@app.route("/gdpr/anonymize-data", methods=["POST"])
@login_required
def gdpr_anonymize_data():
    """Anonymize user data (GDPR Article 17)"""
    if not current_user.is_admin:
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for("dashboard"))
    
    user_id = request.form.get("user_id", type=int)
    if not user_id:
        flash("User ID is required", "danger")
        return redirect(url_for("gdpr_data_subject_info"))
    
    gdpr = get_gdpr_compliance()
    success = gdpr.anonymize_user_data(user_id)
    
    if success:
        flash("User data anonymized successfully", "success")
    else:
        flash("Failed to anonymize user data", "danger")
    
    return redirect(url_for("gdpr_data_subject_info"))

@app.route("/gdpr/delete-data", methods=["POST"])
@login_required
def gdpr_delete_data():
    """Delete user data (Right to be Forgotten - GDPR Article 17)"""
    if not current_user.is_admin:
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for("dashboard"))
    
    user_id = request.form.get("user_id", type=int)
    if not user_id:
        flash("User ID is required", "danger")
        return redirect(url_for("gdpr_data_subject_info"))
    
    gdpr = get_gdpr_compliance()
    success = gdpr.delete_user_data(user_id)
    
    if success:
        flash("User data deleted successfully", "success")
    else:
        flash("Failed to delete user data", "danger")
    
    return redirect(url_for("gdpr_data_subject_info"))

@app.route("/gdpr/retention-report")
@login_required
def gdpr_retention_report():
    """GDPR data retention compliance report"""
    if not current_user.is_admin:
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for("dashboard"))
    
    gdpr = get_gdpr_compliance()
    retention_report = gdpr.get_data_retention_report()
    privacy_policy = gdpr.generate_privacy_policy()
    
    return render_template("gdpr/retention_report.html", 
                         retention_report=retention_report,
                         privacy_policy=privacy_policy)

@app.route("/gdpr/cleanup-expired-data", methods=["POST"])
@login_required
def gdpr_cleanup_expired_data():
    """Clean up data beyond retention period"""
    if not current_user.is_admin:
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for("dashboard"))
    
    gdpr = get_gdpr_compliance()
    cleanup_stats = gdpr.cleanup_expired_data()
    
    flash(f"Cleanup completed: {cleanup_stats['emails_deleted']} emails, "
          f"{cleanup_stats['logs_deleted']} logs, "
          f"{cleanup_stats['file_scans_deleted']} file scans processed", "info")
    
    return redirect(url_for("gdpr_retention_report"))

# ------------------------------
# Enhanced Security Routes
# ------------------------------
@app.route("/security/2fa-setup")
@login_required
def security_2fa_setup():
    """Setup 2FA for user"""
    security = get_security_enhancements()
    secret = security.generate_2fa_secret(current_user.email)
    qr_code = security.generate_2fa_qr_code(current_user.email, secret)
    
    return render_template("security/2fa_setup.html", 
                         secret=secret, 
                         qr_code=qr_code)

@app.route("/security/verify-2fa", methods=["GET", "POST"])
@login_required
def security_verify_2fa():
    """Verify 2FA token"""
    if request.method == "POST":
        token = request.form.get("token")
        secret = request.form.get("secret")
        
        security = get_security_enhancements()
        if security.verify_2fa_token(secret, token):
            session['2fa_verified'] = True
            flash("2FA verification successful", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid 2FA token", "danger")
    
    return render_template("security/verify_2fa.html")

@app.route("/security/password-strength", methods=["POST"])
@login_required
def security_password_strength():
    """Check password strength"""
    password = request.json.get("password", "")
    security = get_security_enhancements()
    strength_analysis = security.check_password_strength(password)
    return jsonify(strength_analysis)

@app.route("/security/recommendations")
@login_required
def security_recommendations():
    """Get security recommendations for user"""
    security = get_security_enhancements()
    recommendations = security.get_security_recommendations(current_user.id)
    return render_template("security/recommendations.html", recommendations=recommendations)

# ------------------------------
# Run App
# ------------------------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="127.0.0.1", port=5000)
