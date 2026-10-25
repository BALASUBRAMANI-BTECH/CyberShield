import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.services.target_service import TargetSecurityService
from backend.services.nessus_service import NessusParserService
from backend.services.burp_service import BurpParserService
from backend.services.report_service import ReportService
from backend.models.database import SessionLocal
from backend.models.models import Vulnerability

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "CyberShield" in data["service"]


def test_dashboard_stats():
    response = client.get("/api/dashboard/stats")
    assert response.status_code == 200
    data = response.json()
    assert data["total_targets"] >= 4
    assert data["total_vulnerabilities"] >= 5
    assert "Critical" in data["severity_counts"]
    assert data["security_score"] >= 0


def test_ssrf_protection_blocked_metadata():
    # Cloud metadata address (AWS / Azure / GCP)
    is_valid, msg, _ = TargetSecurityService.validate_target("http://169.254.169.254/latest/meta-data/")
    assert not is_valid
    assert "SSRF Protection" in msg or "blocked" in msg


def test_allowlist_enforcement():
    # Loopback is valid
    is_valid, msg, host = TargetSecurityService.validate_target("127.0.0.1")
    assert is_valid
    assert host == "127.0.0.1"

    # RFC 1918 Private Lab IP is valid
    is_valid, _, _ = TargetSecurityService.validate_target("192.168.1.50")
    assert is_valid

    # Disallowed public IP without override should be rejected
    is_valid, msg, _ = TargetSecurityService.validate_target("8.8.8.8", allow_public=False)
    assert not is_valid
    assert "outside authorized private lab subnets" in msg


def test_target_registration_ssrf_blocked():
    # Attempting to register cloud metadata endpoint
    res = client.post("/api/targets", json={
        "name": "Malicious Metadata Probe",
        "target_type": "ip",
        "address": "169.254.169.254",
        "description": "Exploit attempt",
        "is_authorized": True
    })
    assert res.status_code == 400
    assert "SSRF Protection" in res.json()["detail"]


def test_nessus_csv_parser():
    sample_csv = NessusParserService.get_fallback_sample_csv()
    findings = NessusParserService.parse_csv(sample_csv)
    assert len(findings) >= 3
    assert any("Log4j" in f["title"] or "156014" in f["title"] for f in findings)
    assert any(f["severity"] == "Critical" for f in findings)


def test_burp_xml_parser():
    sample_xml = BurpParserService.load_sample_report()
    findings = BurpParserService.parse_xml(sample_xml)
    assert len(findings) >= 1
    assert any("XML External Entity" in f["title"] or "XXE" in f["title"] for f in findings)


def test_report_generation_csv_and_pdf():
    db = SessionLocal()
    try:
        findings = db.query(Vulnerability).limit(5).all()
        # Test CSV
        csv_output = ReportService.generate_csv(findings)
        assert "Finding ID" in csv_output
        assert "Vulnerability Title" in csv_output

        # Test PDF
        pdf_bytes = ReportService.generate_pdf(findings)
        assert len(pdf_bytes) > 1000
        assert pdf_bytes.startswith(b"%PDF")
    finally:
        db.close()


def test_vulnerability_status_update():
    # List findings
    res = client.get("/api/vulnerabilities")
    assert res.status_code == 200
    items = res.json()
    assert len(items) > 0
    first_id = items[0]["id"]

    # Update status to 'Fixed'
    patch_res = client.patch(f"/api/vulnerabilities/{first_id}/status", json={"status": "Fixed"})
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "Fixed"
