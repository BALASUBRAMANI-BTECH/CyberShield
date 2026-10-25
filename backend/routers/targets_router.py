from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel

from backend.models.database import get_db
from backend.models.models import Target, AuditLog
from backend.schemas.schemas import TargetCreate, TargetUpdate, TargetOut
from backend.services.target_service import TargetSecurityService

router = APIRouter(prefix="/api/targets", tags=["Targets"])


class ValidateAddressRequest(BaseModel):
    address: str


class ValidateAddressResponse(BaseModel):
    valid: bool
    message: str
    normalized_host: str = ""


@router.get("", response_model=List[TargetOut])
def list_targets(db: Session = Depends(get_db)):
    return db.query(Target).order_by(Target.created_at.desc()).all()


@router.get("/{target_id}", response_model=TargetOut)
def get_target(target_id: int, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target asset not found.")
    return target


@router.post("/validate-address", response_model=ValidateAddressResponse)
def validate_target_address(req: ValidateAddressRequest):
    valid, message, host = TargetSecurityService.validate_target(req.address)
    return ValidateAddressResponse(valid=valid, message=message, normalized_host=host or "")


@router.post("", response_model=TargetOut, status_code=status.HTTP_201_CREATED)
def create_target(payload: TargetCreate, db: Session = Depends(get_db)):
    # 1. SSRF and Allowlist Validation
    is_valid, validation_msg, normalized = TargetSecurityService.validate_target(payload.address)
    if not is_valid:
        # Log security audit violation
        audit = AuditLog(
            action="TARGET_REGISTRATION_BLOCKED",
            actor="sec-analyst",
            target_address=payload.address,
            details=f"Target registration blocked by security policy: {validation_msg}",
            status="BLOCKED"
        )
        db.add(audit)
        db.commit()
        raise HTTPException(status_code=400, detail=validation_msg)

    # 2. Check for duplicate address
    existing = db.query(Target).filter(Target.address == payload.address.strip()).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Target with address '{payload.address}' already exists.")

    new_target = Target(
        name=payload.name.strip(),
        target_type=payload.target_type,
        address=payload.address.strip(),
        description=payload.description or "",
        is_authorized=payload.is_authorized,
        allowlist_verified=True
    )
    db.add(new_target)

    # Log successful registration
    audit = AuditLog(
        action="TARGET_REGISTERED",
        actor="sec-analyst",
        target_address=payload.address,
        details=f"Target '{payload.name}' successfully added and validated for lab testing.",
        status="SUCCESS"
    )
    db.add(audit)
    db.commit()
    db.refresh(new_target)
    return new_target


@router.put("/{target_id}", response_model=TargetOut)
def update_target(target_id: int, payload: TargetUpdate, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")

    if payload.name is not None:
        target.name = payload.name.strip()
    if payload.description is not None:
        target.description = payload.description
    if payload.is_authorized is not None:
        target.is_authorized = payload.is_authorized

    db.commit()
    db.refresh(target)
    return target


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(target_id: int, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")

    audit = AuditLog(
        action="TARGET_DELETED",
        actor="sec-analyst",
        target_address=target.address,
        details=f"Target '{target.name}' and all associated scan data deleted.",
        status="SUCCESS"
    )
    db.add(audit)
    db.delete(target)
    db.commit()
    return None
