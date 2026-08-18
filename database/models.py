from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Target(db.Model):
    __tablename__ = "targets"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    url_or_ip = db.Column(db.String(255), unique=True, nullable=False)
    target_type = db.Column(db.String(50), default="Web Application")
    description = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scans = db.relationship("Scan", backref="target_rel", cascade="all, delete-orphan")

class Scan(db.Model):
    __tablename__ = "scans"
    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey("targets.id"), nullable=False)
    scan_type = db.Column(db.String(50), default="Standard Scan")
    security_score = db.Column(db.Float, default=100.0)
    status = db.Column(db.String(20), default="Completed")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    findings = db.relationship("Finding", backref="scan_rel", cascade="all, delete-orphan")

class Finding(db.Model):
    __tablename__ = "findings"
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    finding_id = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    evidence = db.Column(db.Text, default="")
    description = db.Column(db.Text, default="")
    impact = db.Column(db.Text, default="")
    recommendation = db.Column(db.Text, default="")
    status = db.Column(db.String(20), default="Open")
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
