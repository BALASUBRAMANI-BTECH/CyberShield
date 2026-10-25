from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_

from backend.models.database import get_db
from backend.models.models import Vulnerability, AuditLog
from backend.schemas.schemas import VulnerabilityOut, VulnerabilityStatusUpdate

router = APIRouter(prefix="/api/vulnerabilities", tags=["Vulnerability Management"])


@router.get("", response_model=List[VulnerabilityOut])
def list_vulnerabilities(
    target_id: Optional[int] = Query(None, description="Filter by target asset ID"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    status: Optional[str] = Query(None, description="Filter by status (Open, In Progress, Fixed, Accepted Risk)"),
    source: Optional[str] = Query(None, description="Filter by detection source"),
    search: Optional[str] = Query(None, description="Keyword search in title, CVE, or description"),
    db: Session = Depends(get_db)
):
    query = db.query(Vulnerability)

    if target_id is not None:
        query = query.filter(Vulnerability.target_id == target_id)
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    if status:
        query = query.filter(Vulnerability.status == status)
    if source:
        query = query.filter(Vulnerability.detection_source == source)
    if search:
        kw = f"%{search.strip()}%"
        query = query.filter(
            or_(
                Vulnerability.title.ilike(kw),
                Vulnerability.cve_id.ilike(kw),
                Vulnerability.description.ilike(kw),
                Vulnerability.affected_component.ilike(kw),
                Vulnerability.finding_uid.ilike(kw)
            )
        )

    # Sort: Critical first, then High, Med, Low, Info
    sev_order = {
        "Critical": 1,
        "High": 2,
        "Medium": 3,
        "Low": 4,
        "Info": 5
    }
    results = query.order_by(Vulnerability.created_at.desc()).all()
    # In-memory secondary sort by severity level priority
    results.sort(key=lambda v: sev_order.get(v.severity, 6))
    return results


@router.get("/{vuln_id}", response_model=VulnerabilityOut)
def get_vulnerability(vuln_id: int, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability finding not found.")
    return vuln


@router.patch("/{vuln_id}/status", response_model=VulnerabilityOut)
def update_vulnerability_status(
    vuln_id: int,
    payload: VulnerabilityStatusUpdate,
    db: Session = Depends(get_db)
):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability finding not found.")

    old_status = vuln.status
    vuln.status = payload.status
    db.commit()
    db.refresh(vuln)

    # Audit log entry
    audit = AuditLog(
        action="VULNERABILITY_STATUS_UPDATED",
        actor="sec-analyst",
        target_address=vuln.target.address if vuln.target else "N/A",
        details=f"Finding '{vuln.finding_uid}' status changed from '{old_status}' to '{payload.status}'.",
        status="SUCCESS"
    )
    db.add(audit)
    db.commit()

    return vuln
