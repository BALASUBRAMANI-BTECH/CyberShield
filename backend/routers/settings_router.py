from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.models.database import get_db
from backend.models.models import AuditLog
from backend.schemas.schemas import AuditLogOut
from backend.services.nmap_service import NmapScannerService
from backend.services.zap_service import ZapScannerService
from backend.services.metasploit_service import MetasploitValidationService
from backend.services.target_service import DEFAULT_LAB_ALLOWLIST, BLOCKED_METADATA_IPS

router = APIRouter(prefix="/api/settings", tags=["Settings & Tool Health"])


@router.get("/tools-status")
def get_tools_status():
    nmap_status = NmapScannerService.get_tool_status()
    zap_status = ZapScannerService.check_zap_daemon()
    msf_status = MetasploitValidationService.get_adapter_status()

    return {
        "tools": [
            {
                "id": "nmap",
                "name": "Nmap Network Scanner",
                "status": "Available" if nmap_status["installed"] else "Demo / Simulation Mode Active",
                "installed": nmap_status["installed"],
                "version": nmap_status["version"],
                "binary_path": nmap_status["binary_path"],
                "role": "Host discovery, port scanning, service and version enumeration",
                "setup_guide": "Install Nmap on Windows via https://nmap.org/download.html and add Nmap to system PATH."
            },
            {
                "id": "zap",
                "name": "OWASP ZAP (Zed Attack Proxy)",
                "status": "Active Daemon" if zap_status["active"] else "Built-in DAST & Demo Engine Active",
                "installed": zap_status["active"],
                "version": zap_status["version"],
                "binary_path": zap_status["url"],
                "role": "Automated web application vulnerability auditing and HTTP header security",
                "setup_guide": "Start OWASP ZAP daemon with: 'zap.bat -daemon -port 8080' or run standalone."
            },
            {
                "id": "nessus",
                "name": "Tenable Nessus Parser",
                "status": "Ready (CSV Ingestion Active)",
                "installed": True,
                "version": "v10.x / Professional Export Support",
                "binary_path": "Built-in Parser Engine",
                "role": "Compliance scanning, enterprise CVE identification, and automated solution guidance",
                "setup_guide": "Export any scan as CSV from Tenable Nessus Web UI and upload via New Assessment -> Nessus Import."
            },
            {
                "id": "burp",
                "name": "Burp Suite Professional",
                "status": "Ready (XML/JSON Ingestion Active)",
                "installed": True,
                "version": "PortSwigger Issue Exporter 2024+",
                "binary_path": "Built-in Parser Engine",
                "role": "Deep-tier web application vulnerability assessment and manual verification",
                "setup_guide": "Right click issues in Burp Target/Dashboard -> 'Report issues' -> select XML format."
            },
            {
                "id": "metasploit",
                "name": "Metasploit Validation Framework",
                "status": "Controlled Lab Adapter Active",
                "installed": msf_status["available"],
                "version": "Non-Destructive Proof-of-Concept Engine",
                "binary_path": "Controlled Evidence Logger",
                "role": "Strictly non-destructive lab verification, precondition auditing, and retest evidence",
                "setup_guide": "Metasploit operates via safe controlled verification workflow with mandatory authorization checks."
            }
        ],
        "allowlist_policy": {
            "authorized_cidrs": [str(net) for net in DEFAULT_LAB_ALLOWLIST],
            "blocked_metadata_ranges": [str(net) for net in BLOCKED_METADATA_IPS],
            "enforce_ssrf_protection": True,
            "max_concurrent_scans": 3,
            "scan_timeout_seconds": 180
        }
    }


@router.get("/audit-logs", response_model=List[AuditLogOut])
def get_audit_logs(db: Session = Depends(get_db)):
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(50).all()
