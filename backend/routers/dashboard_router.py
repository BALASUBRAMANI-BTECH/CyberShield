from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.models.database import get_db
from backend.models.models import Target, Scan, Vulnerability
from backend.schemas.schemas import DashboardStats, ScanOut, VulnerabilityOut

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/stats", response_model=DashboardStats)
def get_dashboard_stats(db: Session = Depends(get_db)):
    total_assessments = db.query(Scan).count()
    total_vulnerabilities = db.query(Vulnerability).count()
    total_targets = db.query(Target).count()

    # Severity distribution
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    sev_rows = db.query(Vulnerability.severity, func.count(Vulnerability.id)).group_by(Vulnerability.severity).all()
    for sev, count in sev_rows:
        if sev in severity_counts:
            severity_counts[sev] = count

    # Status counts
    status_counts = {"Open": 0, "In Progress": 0, "Fixed": 0, "Accepted Risk": 0}
    stat_rows = db.query(Vulnerability.status, func.count(Vulnerability.id)).group_by(Vulnerability.status).all()
    for stat, count in stat_rows:
        if stat in status_counts:
            status_counts[stat] = count

    # Source counts
    source_counts = {}
    src_rows = db.query(Vulnerability.detection_source, func.count(Vulnerability.id)).group_by(Vulnerability.detection_source).all()
    for src, count in src_rows:
        source_counts[src] = count

    # Recent scans
    recent_scans = db.query(Scan).order_by(Scan.start_time.desc()).limit(5).all()

    # Recent findings
    recent_findings = db.query(Vulnerability).order_by(Vulnerability.created_at.desc()).limit(6).all()

    # Calculate Enterprise Security Health Score (0 to 100)
    open_critical = db.query(Vulnerability).filter(Vulnerability.severity == "Critical", Vulnerability.status.in_(["Open", "In Progress"])).count()
    open_high = db.query(Vulnerability).filter(Vulnerability.severity == "High", Vulnerability.status.in_(["Open", "In Progress"])).count()
    open_med = db.query(Vulnerability).filter(Vulnerability.severity == "Medium", Vulnerability.status.in_(["Open", "In Progress"])).count()
    open_low = db.query(Vulnerability).filter(Vulnerability.severity == "Low", Vulnerability.status.in_(["Open", "In Progress"])).count()

    deduction = (open_critical * 22) + (open_high * 12) + (open_med * 5) + (open_low * 2)
    score = max(10, min(100, 100 - deduction))

    if open_critical > 0:
        threat_level = "CRITICAL"
    elif open_high > 1:
        threat_level = "HIGH"
    elif open_high > 0 or open_med > 2:
        threat_level = "ELEVATED"
    elif open_med > 0 or open_low > 0:
        threat_level = "MODERATE"
    else:
        threat_level = "SECURE"

    return DashboardStats(
        total_assessments=total_assessments,
        total_vulnerabilities=total_vulnerabilities,
        total_targets=total_targets,
        severity_counts=severity_counts,
        status_counts=status_counts,
        source_counts=source_counts,
        recent_scans=recent_scans,
        recent_findings=recent_findings,
        security_score=score,
        active_threat_level=threat_level
    )
