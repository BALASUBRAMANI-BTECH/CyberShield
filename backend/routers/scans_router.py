import json
import uuid
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form
from sqlalchemy.orm import Session

from backend.models.database import get_db
from backend.models.models import Target, Scan, Vulnerability, AuditLog
from backend.schemas.schemas import ScanStartRequest, ScanOut, VulnerabilityOut
from backend.services.nmap_service import NmapScannerService
from backend.services.zap_service import ZapScannerService
from backend.services.nessus_service import NessusParserService
from backend.services.burp_service import BurpParserService
from backend.services.metasploit_service import MetasploitValidationService

router = APIRouter(prefix="/api/scans", tags=["Assessments & Scans"])


def generate_finding_uid(db: Session) -> str:
    year = datetime.utcnow().year
    count = db.query(Vulnerability).count() + 1
    return f"VAPT-{year}-{count:04d}"


@router.get("", response_model=List[ScanOut])
def list_scans(db: Session = Depends(get_db)):
    return db.query(Scan).order_by(Scan.start_time.desc()).all()


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return scan


@router.get("/{scan_id}/findings", response_model=List[VulnerabilityOut])
def get_scan_findings(scan_id: int, db: Session = Depends(get_db)):
    return db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).order_by(Vulnerability.cvss_score.desc().nullslast()).all()


@router.post("/start", response_model=ScanOut)
def start_scan(req: ScanStartRequest, db: Session = Depends(get_db)):
    # 1. Target verification
    target = db.query(Target).filter(Target.id == req.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")

    if not target.is_authorized:
        raise HTTPException(
            status_code=403,
            detail="Active assessment forbidden: Target is marked as NOT authorized. Enable authorization in Target settings before scanning."
        )

    # 2. Initialize Scan entry
    scan = Scan(
        target_id=target.id,
        scan_name=req.scan_name or f"{req.scan_type.upper()} Assessment - {target.name}",
        scan_type=req.scan_type,
        scan_profile=req.scan_profile,
        status="running",
        is_demo=req.is_demo,
        start_time=datetime.utcnow()
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    raw_output = ""
    findings_to_insert = []
    source_tag = "demo_simulation" if req.is_demo else "real_tool"

    try:
        if req.scan_type == "nmap":
            scan_res = NmapScannerService.execute_scan(
                target_address=target.address,
                profile=req.scan_profile,
                ports=req.ports,
                force_demo=req.is_demo
            )
            raw_output = scan_res["raw_output"]
            source_tag = scan_res["execution_source"]
            scan.is_demo = scan_res["is_demo"]
            findings_to_insert = scan_res["findings"]

        elif req.scan_type == "zap":
            scan_res = ZapScannerService.execute_web_assessment(
                target_url=target.address,
                force_demo=req.is_demo
            )
            raw_output = scan_res["raw_output"]
            source_tag = scan_res["execution_source"]
            scan.is_demo = scan_res["is_demo"]
            findings_to_insert = scan_res["findings"]

        elif req.scan_type == "full_vapt":
            # Run both network and web assessments
            nmap_res = NmapScannerService.execute_scan(target.address, req.scan_profile, req.ports, req.is_demo)
            zap_res = ZapScannerService.execute_web_assessment(target.address, req.is_demo)
            raw_output = f"[--- PHASE 1: NMAP NETWORK ENUMERATION ---]\n{nmap_res['raw_output']}\n\n[--- PHASE 2: OWASP ZAP WEB APPLICATION AUDIT ---]\n{zap_res['raw_output']}"
            source_tag = "real_tool" if not (nmap_res["is_demo"] and zap_res["is_demo"]) else "demo_simulation"
            scan.is_demo = nmap_res["is_demo"] or zap_res["is_demo"]
            findings_to_insert = nmap_res["findings"] + zap_res["findings"]

        elif req.scan_type == "nessus_import":
            # Load sample Nessus report
            csv_data = NessusParserService.load_sample_report()
            findings_to_insert = NessusParserService.parse_csv(csv_data, target.id)
            raw_output = f"[NESSUS IMPORT ENGINE]\nLoaded sample Nessus assessment report.\nIdentified {len(findings_to_insert)} vulnerabilities."
            source_tag = "imported_file"
            scan.is_demo = False

        elif req.scan_type == "burp_import":
            # Load sample Burp report
            xml_data = BurpParserService.load_sample_report()
            findings_to_insert = BurpParserService.parse_xml(xml_data, target.id)
            raw_output = f"[BURP SUITE IMPORT ENGINE]\nLoaded sample Burp Suite XML assessment file.\nIdentified {len(findings_to_insert)} vulnerabilities."
            source_tag = "imported_file"
            scan.is_demo = False

        # Ingest vulnerabilities into database
        stats = {"total": len(findings_to_insert), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for item in findings_to_insert:
            sev = item.get("severity", "Medium")
            if sev in stats:
                stats[sev] += 1

            vuln = Vulnerability(
                scan_id=scan.id,
                target_id=target.id,
                finding_uid=generate_finding_uid(db),
                title=item["title"],
                cve_id=item.get("cve_id"),
                cvss_score=item.get("cvss_score"),
                severity=item.get("severity", "Medium"),
                detection_source=item.get("detection_source", "Automated"),
                verification_status=item.get("verification_status", "Unverified Automated"),
                confidence=item.get("confidence", "Medium"),
                affected_component=item.get("affected_component", target.address),
                description=item["description"],
                technical_impact=item.get("technical_impact", ""),
                business_impact=item.get("business_impact", ""),
                remediation=item.get("remediation", ""),
                raw_evidence=item.get("raw_evidence", ""),
                status="Open",
                created_at=datetime.utcnow()
            )
            db.add(vuln)
            db.commit()

        scan.status = "completed"
        scan.end_time = datetime.utcnow()
        scan.execution_source = source_tag
        scan.raw_output = raw_output
        scan.set_stats(stats)
        db.commit()

        # Audit logging
        audit = AuditLog(
            action="SCAN_COMPLETED",
            actor="sec-analyst",
            target_address=target.address,
            details=f"Scan '{scan.scan_name}' completed. Source: {source_tag}. Findings: {stats['total']}.",
            status="SUCCESS"
        )
        db.add(audit)
        db.commit()

    except Exception as e:
        scan.status = "failed"
        scan.end_time = datetime.utcnow()
        scan.raw_output = f"[ERROR DURING ASSESSMENT]: {str(e)}"
        db.commit()
        raise HTTPException(status_code=500, detail=f"Assessment failed: {str(e)}")

    db.refresh(scan)
    return scan


@router.post("/import/nessus", response_model=ScanOut)
async def import_nessus_csv(
    target_id: int = Form(...),
    scan_name: str = Form("Imported Nessus Assessment"),
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")

    content = await file.read()
    try:
        csv_text = content.decode("utf-8")
    except UnicodeDecodeError:
        csv_text = content.decode("latin-1")

    findings = NessusParserService.parse_csv(csv_text, target.id)

    scan = Scan(
        target_id=target.id,
        scan_name=scan_name,
        scan_type="nessus_import",
        scan_profile="imported_csv",
        status="completed",
        is_demo=False,
        execution_source="imported_file",
        start_time=datetime.utcnow(),
        end_time=datetime.utcnow(),
        raw_output=f"Successfully parsed Nessus CSV '{file.filename}'. Ingested {len(findings)} findings."
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    stats = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in findings:
        sev = item.get("severity", "Medium")
        if sev in stats:
            stats[sev] += 1
        vuln = Vulnerability(
            scan_id=scan.id,
            target_id=target.id,
            finding_uid=generate_finding_uid(db),
            title=item["title"],
            cve_id=item.get("cve_id"),
            cvss_score=item.get("cvss_score"),
            severity=sev,
            detection_source="Nessus",
            verification_status=item.get("verification_status", "Verified / Confirmed"),
            confidence=item.get("confidence", "High"),
            affected_component=item.get("affected_component", target.address),
            description=item["description"],
            technical_impact=item.get("technical_impact", ""),
            business_impact=item.get("business_impact", ""),
            remediation=item.get("remediation", ""),
            raw_evidence=item.get("raw_evidence", ""),
            status="Open",
            created_at=datetime.utcnow()
        )
        db.add(vuln)
        db.commit()

    scan.set_stats(stats)
    db.commit()
    db.refresh(scan)
    return scan


@router.post("/import/burp", response_model=ScanOut)
async def import_burp_xml(
    target_id: int = Form(...),
    scan_name: str = Form("Imported Burp Suite Assessment"),
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")

    content = await file.read()
    try:
        xml_text = content.decode("utf-8")
    except UnicodeDecodeError:
        xml_text = content.decode("latin-1")

    findings = BurpParserService.parse_xml(xml_text, target.id)

    scan = Scan(
        target_id=target.id,
        scan_name=scan_name,
        scan_type="burp_import",
        scan_profile="imported_xml",
        status="completed",
        is_demo=False,
        execution_source="imported_file",
        start_time=datetime.utcnow(),
        end_time=datetime.utcnow(),
        raw_output=f"Parsed Burp Suite XML '{file.filename}'. Ingested {len(findings)} findings."
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    stats = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in findings:
        sev = item.get("severity", "Medium")
        if sev in stats:
            stats[sev] += 1
        vuln = Vulnerability(
            scan_id=scan.id,
            target_id=target.id,
            finding_uid=generate_finding_uid(db),
            title=item["title"],
            cve_id=item.get("cve_id"),
            cvss_score=item.get("cvss_score"),
            severity=sev,
            detection_source="Burp Suite",
            verification_status=item.get("verification_status", "Unverified Automated"),
            confidence=item.get("confidence", "Medium"),
            affected_component=item.get("affected_component", target.address),
            description=item["description"],
            technical_impact=item.get("technical_impact", ""),
            business_impact=item.get("business_impact", ""),
            remediation=item.get("remediation", ""),
            raw_evidence=item.get("raw_evidence", ""),
            status="Open",
            created_at=datetime.utcnow()
        )
        db.add(vuln)
        db.commit()

    scan.set_stats(stats)
    db.commit()
    db.refresh(scan)
    return scan


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    db.delete(scan)
    db.commit()
    return None
