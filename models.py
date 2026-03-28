from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import secrets
import json

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = "user"
    
    id = db.Column(db.Integer, primary_key=True)
    is_admin = db.Column(db.Boolean, default=False)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(190), unique=True, nullable=False)

    # local auth
    password_hash = db.Column(db.String(255), nullable=True)

    # social auth
    google_id = db.Column(db.String(255), unique=True, nullable=True)
    auth_provider = db.Column(db.String(50), default="local")  # local / google / mixed

    # telegram connect
    telegram_chat_id = db.Column(db.String(100), nullable=True)
    telegram_username = db.Column(db.String(120), nullable=True)
    telegram_connected_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    subscription_plan = db.Column(db.String(50), default="free")
    subscription_status = db.Column(db.String(50), default="inactive")
    subscription_start = db.Column(db.DateTime, nullable=True)
    subscription_end = db.Column(db.DateTime, nullable=True)
    
    api_token = db.Column(
        db.String(128),
        unique=True,
        nullable=False,
        default=lambda: secrets.token_hex(32)
    )
    
    def has_active_subscription(self):
        return (
            self.subscription_status == "active"
            and self.subscription_end is not None
            and self.subscription_end > datetime.utcnow()
        )
    
    def get_subscription_plan(self):
        return self.subscription_plan
    
    def is_subscription_active(self):
        return self.has_active_subscription()

    def has_password(self):
        return bool(self.password_hash)

    def has_google_login(self):
        return bool(self.google_id)

    def is_telegram_connected(self):
        return bool(self.telegram_chat_id)

    def __repr__(self):
        return f"<User {self.email}>"


class Project(db.Model):
    __tablename__ = "project"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    domain = db.Column(db.String(255), nullable=True, index=True)
    description = db.Column(db.Text, nullable=True)

    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(255), nullable=True, unique=True)
    verification_method = db.Column(db.String(50), nullable=True)  # meta / html / dns
    verified_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)

    user = db.relationship("User", backref=db.backref("projects", lazy=True, cascade="all, delete-orphan"))
    scans = db.relationship("ScanRecord", backref="project", lazy=True, cascade="all, delete-orphan")

    def ensure_token(self):
        if not self.verification_token:
            self.verification_token = secrets.token_urlsafe(24)

    def verification_meta_tag(self):
        self.ensure_token()
        return f'<meta name="cybrix-verification" content="{self.verification_token}">'

    def verification_html_filename(self):
        self.ensure_token()
        return f"cybrix-{self.verification_token}.html"

    def verification_html_content(self):
        self.ensure_token()
        return f"cybrix-site-verification: {self.verification_token}"

    def __repr__(self):
        return f"<Project {self.name}>"


class ScanRecord(db.Model):
    __tablename__ = "scan_record"

    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(500), nullable=True)
    source = db.Column(db.String(100), nullable=True)
    label = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(100), nullable=True)
    length = db.Column(db.Integer, nullable=True)
    scan_type = db.Column(db.String(50), nullable=True)
    result = db.Column(db.Text, nullable=True)
    risk_score = db.Column(db.Float, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey("project.id", ondelete="SET NULL"), nullable=True)

    user = db.relationship("User", backref=db.backref("scan_records", lazy=True, cascade="all, delete-orphan"))

    def __repr__(self):
        return f"<ScanRecord {self.id} - {self.target}>"


class Subscription(db.Model):
    __tablename__ = "subscription"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False, unique=True)
    plan_name = db.Column(db.String(50), nullable=False, default="free")
    start_date = db.Column(db.DateTime, default=datetime.utcnow)
    end_date = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    auto_renew = db.Column(db.Boolean, default=False)
    
    user = db.relationship("User", backref=db.backref("subscription", uselist=False, cascade="all, delete-orphan"))

    def is_valid(self):
        return self.is_active and self.end_date > datetime.utcnow()
    
    def days_remaining(self):
        if not self.is_valid():
            return 0
        delta = self.end_date - datetime.utcnow()
        return max(0, delta.days)
    
    def __repr__(self):
        return f"<Subscription {self.user_id} {self.plan_name}>"


class LocalScanResult(db.Model):
    __tablename__ = "local_scan_result"
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    target_url = db.Column(db.String(500), nullable=False)
    scan_type = db.Column(db.String(50), default="local_agent")
    findings_json = db.Column(db.Text, nullable=False, default="[]")
    status = db.Column(db.String(50), default="completed")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship("User", backref=db.backref("local_scans", lazy=True, cascade="all, delete-orphan"))
    
    def get_findings(self):
        try:
            return json.loads(self.findings_json)
        except Exception:
            return []
    
    def __repr__(self):
        return f"<LocalScanResult {self.id} - {self.target_url}>"


class ApiUsage(db.Model):
    __tablename__ = "api_usage"
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    endpoint = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship("User", backref=db.backref("api_usages", lazy=True))
    
    def __repr__(self):
        return f"<ApiUsage {self.user_id} - {self.endpoint}>"


class SiteMonitor(db.Model):
    __tablename__ = "site_monitor"
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    target_url = db.Column(db.String(500), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    last_checked_at = db.Column(db.DateTime, nullable=True)
    last_status = db.Column(db.String(50), nullable=True)
    check_interval = db.Column(db.Integer, default=3600)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship("User", backref=db.backref("site_monitors", lazy=True, cascade="all, delete-orphan"))
    
    def __repr__(self):
        return f"<SiteMonitor {self.id} - {self.target_url}>"


class ScanQueue(db.Model):
    __tablename__ = "scan_queue"
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    target_url = db.Column(db.String(500), nullable=False)
    scan_type = db.Column(db.String(50), default="full")
    status = db.Column(db.String(50), default="queued")
    priority = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime, nullable=True)
    finished_at = db.Column(db.DateTime, nullable=True)
    
    user = db.relationship("User", backref=db.backref("scan_queue", lazy=True))
    
    def __repr__(self):
        return f"<ScanQueue {self.id} - {self.target_url} - {self.status}>"


class Team(db.Model):
    __tablename__ = "team"
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    owner = db.relationship("User", foreign_keys=[owner_id], backref=db.backref("owned_teams", lazy=True))
    members = db.relationship("TeamMember", backref="team", lazy=True, cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Team {self.name}>"


class TeamMember(db.Model):
    __tablename__ = "team_member"
    
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(db.Integer, db.ForeignKey("team.id", ondelete="CASCADE"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    role = db.Column(db.String(50), default="member")
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship("User", backref=db.backref("team_memberships", lazy=True, cascade="all, delete-orphan"))
    
    def __repr__(self):
        return f"<TeamMember {self.user_id} in {self.team_id}>"


class PaymentTransaction(db.Model):
    __tablename__ = "payment_transaction"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    provider = db.Column(db.String(50), nullable=False, default="fake")
    plan = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(50), default="pending")
    provider_transaction_id = db.Column(db.String(255), nullable=True)
    payment_url = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    paid_at = db.Column(db.DateTime, nullable=True)
    
    user = db.relationship("User", backref=db.backref("payments", lazy=True, cascade="all, delete-orphan"))
    
    def is_successful(self):
        return self.status == "success"
    
    def mark_as_successful(self):
        self.status = "success"
        self.paid_at = datetime.utcnow()
    
    def __repr__(self):
        return f"<PaymentTransaction {self.id} - {self.plan} - {self.status}>"


class Notification(db.Model):
    __tablename__ = "notification"
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50), default="info")
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship("User", backref=db.backref("notifications", lazy=True, cascade="all, delete-orphan"))
    
    def mark_as_read(self):
        self.is_read = True
    
    def __repr__(self):
        return f"<Notification {self.id} - {self.title}>"
class AnalysisResult(db.Model):
    __tablename__ = "analysis_result"
    
    id = db.Column(db.Integer, primary_key=True)
    feature = db.Column(db.String(100), nullable=False)
    input_data = db.Column(db.Text, nullable=False)
    result = db.Column(db.Text, nullable=False)
    confidence = db.Column(db.Float, default=1.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<AnalysisResult {self.id} - {self.feature}>"

class ActivityLog(db.Model):
    __tablename__ = "activity_log"
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship("User", backref=db.backref("activity_logs", lazy=True))
    
    def __repr__(self):
        return f"<ActivityLog {self.id} - {self.action}>"