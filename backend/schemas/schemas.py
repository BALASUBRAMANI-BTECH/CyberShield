from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


# Target Schemas
class TargetBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=120)
    target_type: str = Field("ip", pattern="^(ip|hostname|url|cidr)$")
    address: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = ""
    is_authorized: bool = True


class TargetCreate(TargetBase):
    pass


class TargetUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_authorized: Optional[bool] = None


class TargetOut(TargetBase):
    id: int
    allowlist_verified: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# Vulnerability Schemas
class VulnerabilityBase(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    severity: str = Field("Medium", pattern="^(Critical|High|Medium|Low|Info)$")
    detection_source: str
    verification_status: str = "Unverified Automated"
    confidence: str = "Medium"
    affected_component: Optional[str] = ""
    description: str
    technical_impact: Optional[str] = ""
    business_impact: Optional[str] = ""
    remediation: Optional[str] = ""
    raw_evidence: Optional[str] = ""
    status: str = Field("Open", pattern="^(Open|In Progress|Fixed|Accepted Risk)$")


class VulnerabilityCreate(VulnerabilityBase):
    target_id: int
    scan_id: Optional[int] = None
    finding_uid: Optional[str] = None


class VulnerabilityStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(Open|In Progress|Fixed|Accepted Risk)$")


class VulnerabilityOut(VulnerabilityBase):
    id: int
    scan_id: Optional[int] = None
    target_id: int
    finding_uid: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# Metasploit Validation Record Schemas
class MetasploitRecordCreate(BaseModel):
    vulnerability_id: Optional[int] = None
    target_id: int
    test_case_name: str
    module_type: str = "auxiliary/scanner"
    preconditions: str
    authorization_proof: str
    risk_assessment: Optional[str] = ""
    execution_mode: str = "controlled_simulation"


class MetasploitRecordOut(BaseModel):
    id: int
    vulnerability_id: Optional[int]
    target_id: int
    test_case_name: str
    module_type: str
    preconditions: str
    authorization_proof: str
    evidence_observed: str
    risk_assessment: str
    remediation_status: str
    verified_by: str
    execution_mode: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# Scan Schemas
class ScanStartRequest(BaseModel):
    target_id: int
    scan_name: str = "Automated Security Assessment"
    scan_type: str = Field(..., pattern="^(nmap|zap|burp_import|nessus_import|metasploit_validation|full_vapt)$")
    scan_profile: str = "standard"  # quick, standard, intense, owasp_top10
    is_demo: bool = False
    ports: Optional[str] = None  # e.g. "80,443,8080,3000"


class ScanOut(BaseModel):
    id: int
    target_id: int
    scan_name: str
    scan_type: str
    scan_profile: str
    status: str
    is_demo: bool
    execution_source: str
    start_time: datetime
    end_time: Optional[datetime]
    summary_stats: Optional[str]
    raw_output: Optional[str]
    target: Optional[TargetOut] = None

    model_config = ConfigDict(from_attributes=True)


# Dashboard Statistics Schemas
class DashboardStats(BaseModel):
    total_assessments: int
    total_vulnerabilities: int
    total_targets: int
    severity_counts: Dict[str, int]
    status_counts: Dict[str, int]
    source_counts: Dict[str, int]
    recent_scans: List[ScanOut]
    recent_findings: List[VulnerabilityOut]
    security_score: int
    active_threat_level: str


# Audit Log Schemas
class AuditLogOut(BaseModel):
    id: int
    timestamp: datetime
    action: str
    actor: str
    target_address: str
    details: str
    status: str

    model_config = ConfigDict(from_attributes=True)
