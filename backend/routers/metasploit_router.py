from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.models.database import get_db
from backend.models.models import Target, Vulnerability, MetasploitValidationRecord, AuditLog
from backend.schemas.schemas import MetasploitRecordCreate, MetasploitRecordOut
from backend.services.metasploit_service import MetasploitValidationService

router = APIRouter(prefix="/api/metasploit", tags=["Metasploit Validation"])


@router.get("/status")
def get_msf_status():
    return MetasploitValidationService.get_adapter_status()


@router.get("/records", response_model=List[MetasploitRecordOut])
def list_validation_records(db: Session = Depends(get_db)):
    return db.query(MetasploitValidationRecord).order_by(MetasploitValidationRecord.created_at.desc()).all()


@router.post("/validate", response_model=MetasploitRecordOut)
def run_validation_case(payload: MetasploitRecordCreate, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == payload.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target asset not found.")

    if not target.is_authorized:
        raise HTTPException(
            status_code=403,
            detail="Penetration test validation forbidden: Target is marked as NOT authorized."
        )

    # Resolve vulnerability title if linked
    vuln_title = None
    if payload.vulnerability_id:
        v = db.query(Vulnerability).filter(Vulnerability.id == payload.vulnerability_id).first()
        if v:
            vuln_title = v.title

    result = MetasploitValidationService.run_controlled_validation(
        target_address=target.address,
        test_case_name=payload.test_case_name,
        module_type=payload.module_type,
        preconditions=payload.preconditions,
        authorization_proof=payload.authorization_proof,
        vulnerability_title=vuln_title
    )

    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Validation rejected."))

    # Save validation record
    record = MetasploitValidationRecord(
        vulnerability_id=payload.vulnerability_id,
        target_id=target.id,
        test_case_name=payload.test_case_name,
        module_type=payload.module_type,
        preconditions=payload.preconditions,
        authorization_proof=payload.authorization_proof,
        evidence_observed=result["evidence_observed"],
        risk_assessment=result["risk_assessment"],
        remediation_status=result["remediation_status"],
        verified_by=result["verified_by"],
        execution_mode=result["execution_mode"]
    )
    db.add(record)

    # Audit log
    audit = AuditLog(
        action="METASPLOIT_VALIDATION_EXECUTED",
        actor="secops-pen-tester",
        target_address=target.address,
        details=f"Controlled validation '{payload.test_case_name}' executed. Result: {result['remediation_status']}.",
        status="SUCCESS"
    )
    db.add(audit)
    db.commit()
    db.refresh(record)

    return record
