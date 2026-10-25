import json
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, Float, DateTime, ForeignKey
)
from sqlalchemy.orm import relationship
from backend.models.database import Base


class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(120), nullable=False)
    target_type = Column(String(20), default="ip")  # ip, hostname, url, cidr
    address = Column(String(255), nullable=False, unique=True, index=True)
    description = Column(Text, default="")
    is_authorized = Column(Boolean, default=True)
    allowlist_verified = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="target", cascade="all, delete-orphan")
    validation_records = relationship("MetasploitValidationRecord", back_populates="target", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    scan_name = Column(String(150), nullable=False)
    scan_type = Column(String(50), nullable=False)  # nmap, zap, burp_import, nessus_import, metasploit_validation, full_vapt
    scan_profile = Column(String(50), default="standard")
    status = Column(String(30), default="queued")  # queued, running, completed, failed
    is_demo = Column(Boolean, default=False)
    execution_source = Column(String(40), default="demo_simulation")  # real_tool, imported_file, demo_simulation
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    raw_output = Column(Text, default="")
    summary_stats = Column(Text, default="{}")  # JSON string

    target = relationship("Target", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")

    def get_stats(self):
        try:
            return json.loads(self.summary_stats) if self.summary_stats else {}
        except Exception:
            return {}

    def set_stats(self, stats_dict):
        self.summary_stats = json.dumps(stats_dict)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    finding_uid = Column(String(30), unique=True, index=True)
    title = Column(String(200), nullable=False, index=True)
    cve_id = Column(String(50), nullable=True, index=True)
    cvss_score = Column(Float, nullable=True)
    severity = Column(String(20), nullable=False, index=True)  # Critical, High, Medium, Low, Info
    detection_source = Column(String(50), nullable=False)  # Nmap, OWASP ZAP, Burp Suite, Nessus, Metasploit, Manual Audit
    verification_status = Column(String(50), default="Unverified Automated")  # Unverified Automated, Heuristic Alert, Verified / Confirmed, Simulated Finding
    confidence = Column(String(20), default="Medium")  # High, Medium, Low
    affected_component = Column(String(200), default="")
    description = Column(Text, nullable=False)
    technical_impact = Column(Text, default="")
    business_impact = Column(Text, default="")
    remediation = Column(Text, default="")
    raw_evidence = Column(Text, default="")
    status = Column(String(30), default="Open", index=True)  # Open, In Progress, Fixed, Accepted Risk
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scan = relationship("Scan", back_populates="vulnerabilities")
    target = relationship("Target", back_populates="vulnerabilities")
    validation_records = relationship("MetasploitValidationRecord", back_populates="vulnerability")


class MetasploitValidationRecord(Base):
    __tablename__ = "metasploit_validation_records"

    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    test_case_name = Column(String(200), nullable=False)
    module_type = Column(String(100), default="auxiliary/scanner")
    preconditions = Column(Text, default="")
    authorization_proof = Column(Text, default="")
    evidence_observed = Column(Text, default="")
    risk_assessment = Column(Text, default="")
    remediation_status = Column(String(50), default="Validated Vulnerable")
    verified_by = Column(String(100), default="Lead SecOps Engineer")
    execution_mode = Column(String(50), default="controlled_simulation")
    created_at = Column(DateTime, default=datetime.utcnow)

    vulnerability = relationship("Vulnerability", back_populates="validation_records")
    target = relationship("Target", back_populates="validation_records")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    action = Column(String(100), nullable=False)
    actor = Column(String(80), default="analyst")
    target_address = Column(String(255), default="")
    details = Column(Text, default="")
    status = Column(String(30), default="SUCCESS")
