from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import json

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    email = Column(String(100), unique=True, index=True)
    hashed_password = Column(String(200))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    scans = relationship("ScanResult", back_populates="user")

class ScanResult(Base):
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    target_url = Column(String(500))
    scan_type = Column(String(50))
    status = Column(String(20), default="pending")
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    vulnerabilities = Column(JSON, default=list)
    summary = Column(JSON, default=dict)
    report_path = Column(String(500), nullable=True)
    
    user = relationship("User", back_populates="scans")
    
    def to_dict(self):
        return {
            "id": self.id,
            "target_url": self.target_url,
            "scan_type": self.scan_type,
            "status": self.status,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "vulnerabilities": self.vulnerabilities,
            "summary": self.summary
        }

class VulnerabilityDB(Base):
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200))
    severity = Column(String(20))
    description = Column(Text)
    remediation = Column(Text)
    cve_id = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)