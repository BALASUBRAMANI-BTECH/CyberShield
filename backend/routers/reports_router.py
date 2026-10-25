from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from backend.models.database import get_db
from backend.models.models import Target, Scan, Vulnerability, AuditLog
from backend.services.report_service import ReportService

router = APIRouter(prefix="/api/reports", tags=["Reports & Exports"])


@router.get("/summary")
def get_report_summary(
    scan_id: Optional[int] = Query(None),
    target_id: Optional[int] = Query(None),
    db: Session = Depends(get_db)
):
    query = db.query(Vulnerability)
    if scan_id:
        query = query.filter(Vulnerability.scan_id == scan_id)
    if target_id:
        query = query.filter(Vulnerability.target_id == target_id)

    findings = query.all()
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        if f.severity in sev_counts:
            sev_counts[f.severity] += 1

    target = db.query(Target).filter(Target.id == target_id).first() if target_id else None
    scan = db.query(Scan).filter(Scan.id == scan_id).first() if scan_id else None

    return {
        "total_findings": len(findings),
        "severity_breakdown": sev_counts,
        "target_name": target.name if target else "All Enterprise Assets",
        "target_address": target.address if target else "Multiple In-Scope Subnets",
        "scan_title": scan.scan_name if scan else "Aggregated Enterprise Security Assessment",
        "standards": ["OWASP Top 10", "NIST SP 800-115", "PTES"],
        "export_formats": ["PDF Executive Report", "CSV Technical Data"]
    }


@router.get("/pdf")
def download_pdf_report(
    scan_id: Optional[int] = Query(None),
    target_id: Optional[int] = Query(None),
    db: Session = Depends(get_db)
):
    query = db.query(Vulnerability)
    target = None
    scan = None

    if scan_id:
        query = query.filter(Vulnerability.scan_id == scan_id)
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            target = scan.target
    elif target_id:
        query = query.filter(Vulnerability.target_id == target_id)
        target = db.query(Target).filter(Target.id == target_id).first()

    findings = query.order_by(Vulnerability.cvss_score.desc().nullslast()).all()

    pdf_bytes = ReportService.generate_pdf(
        findings=findings,
        target_info=target,
        scan_info=scan
    )

    filename = f"VAPT_Report_{scan_id or 'All'}_{datetime_now_str()}.pdf"

    # Audit log
    audit = AuditLog(
        action="REPORT_GENERATED_PDF",
        actor="sec-analyst",
        target_address=target.address if target else "ALL",
        details=f"Executive PDF Report generated ({len(findings)} findings).",
        status="SUCCESS"
    )
    db.add(audit)
    db.commit()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get("/csv")
def download_csv_report(
    scan_id: Optional[int] = Query(None),
    target_id: Optional[int] = Query(None),
    db: Session = Depends(get_db)
):
    query = db.query(Vulnerability)
    if scan_id:
        query = query.filter(Vulnerability.scan_id == scan_id)
    if target_id:
        query = query.filter(Vulnerability.target_id == target_id)

    findings = query.order_by(Vulnerability.cvss_score.desc().nullslast()).all()
    csv_str = ReportService.generate_csv(findings)

    filename = f"VAPT_Findings_Export_{scan_id or 'All'}_{datetime_now_str()}.csv"

    # Audit log
    audit = AuditLog(
        action="REPORT_GENERATED_CSV",
        actor="sec-analyst",
        target_address="ALL",
        details=f"CSV Technical Export downloaded ({len(findings)} findings).",
        status="SUCCESS"
    )
    db.add(audit)
    db.commit()

    return Response(
        content=csv_str,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


def datetime_now_str():
    from datetime import datetime
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")
