from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(190), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    subscription_plan = db.Column(db.String(50), default="free")
    subscription_status = db.Column(db.String(50), default="inactive")
    subscription_start = db.Column(db.DateTime, nullable=True)
    subscription_end = db.Column(db.DateTime, nullable=True)

    def has_active_subscription(self):
        return (
            self.subscription_status == "active"
            and self.subscription_end is not None
            and self.subscription_end > datetime.utcnow()
        )
class Project(db.Model):
    __tablename__ = "project"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    def __repr__(self):
        return f"<Project {self.name}>"


class ScanRecord(db.Model):
    __tablename__ = "scan_record"

    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(255), nullable=True)
    scan_type = db.Column(db.String(50), nullable=True)
    result = db.Column(db.Text, nullable=True)
    risk_score = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey("project.id"), nullable=True)

    def __repr__(self):
        return f"<ScanRecord {self.id}>"
class Subscription(db.Model):
    __tablename__ = "subscription"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, unique=True)
    plan_name = db.Column(db.String(50), nullable=False, default="free")   # free, professional, corporate
    start_date = db.Column(db.DateTime, default=datetime.utcnow)
    end_date = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)

    def is_valid(self):
        return self.is_active and self.end_date > datetime.utcnow()

    def __repr__(self):
        return f"<Subscription {self.user_id} {self.plan_name}>"