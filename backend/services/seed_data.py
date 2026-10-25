import json
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from backend.models.models import Target, Scan, Vulnerability, MetasploitValidationRecord, AuditLog


def seed_database_if_empty(db: Session):
    """Populates realistic authorized lab targets, completed scans, and findings."""
    if db.query(Target).count() > 0:
        return  # Already seeded

    # 1. Create Authorized Lab Targets
    t_local = Target(
        name="Localhost Development Host",
        target_type="ip",
        address="127.0.0.1",
        description="Local system loopback interface for initial service enumeration and local API testing.",
        is_authorized=True,
        allowlist_verified=True,
        created_at=datetime.utcnow() - timedelta(days=5)
    )

    t_juice = Target(
        name="OWASP Juice Shop Lab",
        target_type="url",
        address="http://localhost:3000",
        description="Intentionally vulnerable modern JavaScript e-commerce application (OWASP Top 10 evaluation target).",
        is_authorized=True,
        allowlist_verified=True,
        created_at=datetime.utcnow() - timedelta(days=4)
    )

    t_dvwa = Target(
        name="DVWA Isolated Lab Node",
        target_type="url",
        address="http://192.168.56.101/dvwa",
        description="Damn Vulnerable Web Application running in an isolated host-only virtualization subnet.",
        is_authorized=True,
        allowlist_verified=True,
        created_at=datetime.utcnow() - timedelta(days=3)
    )

    t_metasploitable = Target(
        name="Metasploitable 2 Vulnerable Linux Node",
        target_type="ip",
        address="192.168.56.102",
        description="Intentionally vulnerable Linux distribution for network service penetration testing and validation.",
        is_authorized=True,
        allowlist_verified=True,
        created_at=datetime.utcnow() - timedelta(days=2)
    )

    db.add_all([t_local, t_juice, t_dvwa, t_metasploitable])
    db.commit()
    db.refresh(t_local)
    db.refresh(t_juice)
    db.refresh(t_dvwa)
    db.refresh(t_metasploitable)

    # 2. Create Realistic Scans
    scan_nmap = Scan(
        target_id=t_local.id,
        scan_name="Baseline Network & Service Version Discovery",
        scan_type="nmap",
        scan_profile="standard",
        status="completed",
        is_demo=True,
        execution_source="demo_simulation",
        start_time=datetime.utcnow() - timedelta(days=2, hours=3),
        end_time=datetime.utcnow() - timedelta(days=2, hours=2, minutes=58),
        raw_output="""Starting Nmap 7.94 ( https://nmap.org ) at 2026-10-23 05:30 UTC
Nmap scan report for 127.0.0.1
Host is up (0.00030s latency).
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu
80/tcp   open  http        Apache httpd 2.4.49 ((Debian))
|_http-server-header: Apache/2.4.49
3000/tcp open  http        Node.js Express framework
3306/tcp open  mysql       MySQL 5.7.34
Nmap done: 1 IP address scanned in 2.38 seconds""",
        summary_stats=json.dumps({"total": 3, "critical": 1, "high": 0, "medium": 1, "low": 1, "info": 0})
    )

    scan_zap = Scan(
        target_id=t_juice.id,
        scan_name="OWASP Top 10 Web Application Assessment",
        scan_type="zap",
        scan_profile="owasp_top10",
        status="completed",
        is_demo=True,
        execution_source="demo_simulation",
        start_time=datetime.utcnow() - timedelta(days=1, hours=5),
        end_time=datetime.utcnow() - timedelta(days=1, hours=4, minutes=45),
        raw_output="""[OWASP ZAP 2.14.0 Core Scan Engine]
Target URL: http://localhost:3000
Spider crawl discovered 42 endpoints.
Alerts generated: SQL Injection (CWE-89), Stored XSS (CWE-79), Missing CSP Header.""",
        summary_stats=json.dumps({"total": 3, "critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0})
    )

    scan_nessus = Scan(
        target_id=t_metasploitable.id,
        scan_name="Quarterly Compliance & Vulnerability Audit",
        scan_type="nessus_import",
        scan_profile="comprehensive",
        status="completed",
        is_demo=False,
        execution_source="imported_file",
        start_time=datetime.utcnow() - timedelta(hours=8),
        end_time=datetime.utcnow() - timedelta(hours=7, minutes=50),
        raw_output="Nessus CSV Report successfully parsed and imported. 4 vulnerabilities ingested.",
        summary_stats=json.dumps({"total": 4, "critical": 1, "high": 1, "medium": 1, "low": 1, "info": 0})
    )

    db.add_all([scan_nmap, scan_zap, scan_nessus])
    db.commit()
    db.refresh(scan_nmap)
    db.refresh(scan_zap)
    db.refresh(scan_nessus)

    # 3. Create Seed Vulnerabilities
    findings = [
        # Scan 1 Findings (Nmap)
        Vulnerability(
            scan_id=scan_nmap.id,
            target_id=t_local.id,
            finding_uid="VAPT-2024-001",
            title="Apache HTTP Server 2.4.49 Remote Code Execution & Path Traversal",
            cve_id="CVE-2021-41773",
            cvss_score=9.8,
            severity="Critical",
            detection_source="Nmap",
            verification_status="Simulated Finding",
            confidence="High",
            affected_component="Port 80/tcp (Apache 2.4.49)",
            description="Nmap version detection identified Apache HTTP Server 2.4.49. A flaw in URI path normalization in Apache HTTP Server 2.4.49 allows an attacker to map URLs to files outside the expected document root (Path Traversal) and execute CGI scripts remotely.",
            technical_impact="Complete unauthenticated remote code execution and reading of sensitive local configuration files.",
            business_impact="Catastrophic compromise of host confidentiality and potential lateral movement vector into corporate networks.",
            remediation="Upgrade Apache HTTP Server immediately to version 2.4.51 or higher. Disable CGI execution if not required.",
            raw_evidence="PORT 80/tcp open http Apache httpd 2.4.49 ((Debian))\nServer: Apache/2.4.49",
            status="In Progress",
            created_at=datetime.utcnow() - timedelta(days=2, hours=3)
        ),
        Vulnerability(
            scan_id=scan_nmap.id,
            target_id=t_local.id,
            finding_uid="VAPT-2024-002",
            title="MySQL Database Port Exposed Without Network Access Restrictions",
            cve_id=None,
            cvss_score=6.5,
            severity="Medium",
            detection_source="Nmap",
            verification_status="Simulated Finding",
            confidence="High",
            affected_component="Port 3306/tcp (MySQL 5.7.34)",
            description="The MySQL database listener port 3306 was found open and accessible across the network boundary, increasing exposure to brute force attacks.",
            technical_impact="Direct brute-force exposure and database authentication testing.",
            business_impact="Risk of unauthorized customer database dumping if default passwords exist.",
            remediation="Bind MySQL strictly to 127.0.0.1 in my.cnf and enforce firewall iptables restrictions.",
            raw_evidence="PORT 3306/tcp open mysql MySQL 5.7.34",
            status="Open",
            created_at=datetime.utcnow() - timedelta(days=2, hours=3)
        ),
        Vulnerability(
            scan_id=scan_nmap.id,
            target_id=t_local.id,
            finding_uid="VAPT-2024-003",
            title="OpenSSH Server Banner Information Disclosure",
            cve_id=None,
            cvss_score=3.7,
            severity="Low",
            detection_source="Nmap",
            verification_status="Simulated Finding",
            confidence="High",
            affected_component="Port 22/tcp (OpenSSH 8.9p1)",
            description="The SSH service exposes its exact software version in the banner during initial protocol negotiation.",
            technical_impact="Facilitates reconnaissance by attackers identifying known OS distribution and package versions.",
            business_impact="Low operational impact; aids adversary reconnaissance phase.",
            remediation="Modify sshd_config or banner settings where permissible.",
            raw_evidence="PORT 22/tcp open ssh OpenSSH 8.9p1 Ubuntu",
            status="Accepted Risk",
            created_at=datetime.utcnow() - timedelta(days=2, hours=3)
        ),

        # Scan 2 Findings (OWASP ZAP)
        Vulnerability(
            scan_id=scan_zap.id,
            target_id=t_juice.id,
            finding_uid="VAPT-2024-004",
            title="SQL Injection in User Authentication Endpoint (OWASP A03:2021)",
            cve_id="CWE-89",
            cvss_score=9.4,
            severity="Critical",
            detection_source="OWASP ZAP",
            verification_status="Heuristic Alert",
            confidence="Medium",
            affected_component="http://localhost:3000/rest/user/login (email param)",
            description="Automated payload injection detected potential SQL syntax error and boolean differentiation when testing payload `' OR 1=1--` against login handler.",
            technical_impact="Bypass of authentication controls, unauthorized administrative session acquisition, and database exfiltration.",
            business_impact="High risk of customer personal data breach and regulatory compliance penalties.",
            remediation="Implement parameterized queries and input normalization using ORM frameworks. Avoid raw string concatenation in SQL expressions.",
            raw_evidence="POST /rest/user/login\nPayload: {\"email\":\"' OR 1=1--\",\"password\":\"foo\"}\nResponse: SQLITE_ERROR: unrecognized token",
            status="Open",
            created_at=datetime.utcnow() - timedelta(days=1, hours=5)
        ),
        Vulnerability(
            scan_id=scan_zap.id,
            target_id=t_juice.id,
            finding_uid="VAPT-2024-005",
            title="Reflected Cross-Site Scripting (XSS) in Search Endpoint (OWASP A03:2021)",
            cve_id="CWE-79",
            cvss_score=7.5,
            severity="High",
            detection_source="OWASP ZAP",
            verification_status="Heuristic Alert",
            confidence="Medium",
            affected_component="http://localhost:3000/#/search?q=<script>",
            description="Input reflected unencoded into the response body. Payload `<svg onload=alert(1)>` was observed in client-rendered DOM without contextual HTML entity encoding.",
            technical_impact="Arbitrary JavaScript execution inside client browsers.",
            business_impact="Session hijacking, credential theft, and unauthorized user impersonation.",
            remediation="Implement contextual output encoding (e.g., DOMPurify) and configure strict Content-Security-Policy headers.",
            raw_evidence="GET /#/search?q=%3Csvg%20onload=alert(1)%3E\nReflected in search header block.",
            status="In Progress",
            created_at=datetime.utcnow() - timedelta(days=1, hours=5)
        ),
        Vulnerability(
            scan_id=scan_zap.id,
            target_id=t_juice.id,
            finding_uid="VAPT-2024-006",
            title="Missing Content-Security-Policy (CSP) Defense Header",
            cve_id="CWE-1021",
            cvss_score=5.4,
            severity="Medium",
            detection_source="OWASP ZAP",
            verification_status="Verified / Confirmed",
            confidence="High",
            affected_component="http://localhost:3000/ (HTTP Response Headers)",
            description="The HTTP response does not specify a Content-Security-Policy (CSP) header. CSP is a primary defense-in-depth header to restrict unauthorized script execution and framing.",
            technical_impact="Allows malicious injected scripts to fetch external payloads and transmit extracted credentials.",
            business_impact="Elevates the severity of XSS and clickjacking vulnerabilities across the application.",
            remediation="Define a strong CSP header restricting script-src to 'self' and disabling inline script execution.",
            raw_evidence="Response headers omitted Content-Security-Policy header completely.",
            status="Open",
            created_at=datetime.utcnow() - timedelta(days=1, hours=5)
        ),

        # Scan 3 Findings (Nessus Imported)
        Vulnerability(
            scan_id=scan_nessus.id,
            target_id=t_metasploitable.id,
            finding_uid="VAPT-2024-007",
            title="[156014] Apache Log4j Remote Code Execution (Log4Shell)",
            cve_id="CVE-2021-44228",
            cvss_score=10.0,
            severity="Critical",
            detection_source="Nessus",
            verification_status="Verified / Confirmed",
            confidence="High",
            affected_component="192.168.56.102:8080/tcp",
            description="Apache Log4j versions 2.0-beta9 through 2.14.1 JNDI features do not protect against attacker-controlled LDAP and other JNDI endpoints. An attacker can execute arbitrary code loaded from remote servers.",
            technical_impact="Unauthenticated full remote code execution under the privileges of the JVM process.",
            business_impact="Total compromise of enterprise server, persistent backdoor deployment, and data destruction.",
            remediation="Upgrade Log4j to version 2.17.1 or higher, or set JVM system property -Dlog4j2.formatMsgNoLookups=true.",
            raw_evidence="Plugin Output:\nJNDI lookup payload triggered DNS token callback on test-listener.",
            status="Open",
            created_at=datetime.utcnow() - timedelta(hours=8)
        ),
        Vulnerability(
            scan_id=scan_nessus.id,
            target_id=t_metasploitable.id,
            finding_uid="VAPT-2024-008",
            title="[187311] OpenSSH Terrapin Attack Prefix Truncation Vulnerability",
            cve_id="CVE-2023-48795",
            cvss_score=8.1,
            severity="High",
            detection_source="Nessus",
            verification_status="Verified / Confirmed",
            confidence="High",
            affected_component="192.168.56.102:22/tcp",
            description="The SSH server uses cryptographic ciphers susceptible to sequence number manipulation, allowing adversaries to downgrade connection security.",
            technical_impact="Handshake sequence manipulation and security extension downgrades.",
            business_impact="Weakened cryptographic protection for remote system administration sessions.",
            remediation="Upgrade OpenSSH to version 9.6p1 or newer, or disable ChaCha20-Poly1305 and CBC ciphers with ETM.",
            raw_evidence="Observed chacha20-poly1305@openssh.com cipher in SSH KEX negotiation.",
            status="Fixed",
            created_at=datetime.utcnow() - timedelta(hours=8)
        ),
        Vulnerability(
            scan_id=scan_nessus.id,
            target_id=t_metasploitable.id,
            finding_uid="VAPT-2024-009",
            title="[104743] TLS 1.0 and 1.1 Deprecated Protocol Enabled",
            cve_id=None,
            cvss_score=5.9,
            severity="Medium",
            detection_source="Nessus",
            verification_status="Verified / Confirmed",
            confidence="High",
            affected_component="192.168.56.102:443/tcp",
            description="The remote service accepts connections encrypted using TLS 1.0 or TLS 1.1. These protocol versions have known cipher suite deficiencies (BEAST, POODLE) and have been deprecated by RFC 8996.",
            technical_impact="Vulnerable to cryptographic eavesdropping and downgrade attacks.",
            business_impact="PCI-DSS and HIPAA non-compliance.",
            remediation="Disable TLS 1.0 and TLS 1.1. Enforce TLS 1.2 and TLS 1.3 exclusively.",
            raw_evidence="Offered TLSv1.0 with cipher TLS_RSA_WITH_AES_128_CBC_SHA",
            status="Open",
            created_at=datetime.utcnow() - timedelta(hours=8)
        ),
        Vulnerability(
            scan_id=scan_nessus.id,
            target_id=t_metasploitable.id,
            finding_uid="VAPT-2024-010",
            title="[10884] SNMP Agent Default Community Name (public)",
            cve_id=None,
            cvss_score=3.2,
            severity="Low",
            detection_source="Nessus",
            verification_status="Verified / Confirmed",
            confidence="High",
            affected_component="192.168.56.102:161/udp",
            description="The remote SNMP daemon responds to default community string 'public'. An unauthenticated attacker can query the SNMP agent to enumerate network interfaces, routing tables, and running processes.",
            technical_impact="Internal network topology and process enumeration.",
            business_impact="Information disclosure facilitating lateral movement planning.",
            remediation="Change the default SNMP community strings or migrate to SNMPv3 with SHA/AES authentication and privacy.",
            raw_evidence="SNMPv2c response obtained for community string: public",
            status="Open",
            created_at=datetime.utcnow() - timedelta(hours=8)
        )
    ]

    db.add_all(findings)
    db.commit()

    # 4. Controlled Metasploit Validation Record
    msf_record = MetasploitValidationRecord(
        vulnerability_id=findings[0].id,
        target_id=t_local.id,
        test_case_name="Apache 2.4.49 Path Traversal Proof-of-Concept Validation",
        module_type="auxiliary/scanner/http/apache_normalize_path",
        preconditions="Target isolated in lab subnet; port 80/tcp verified open; ROE document ROE-LAB-2024 signed.",
        authorization_proof="ROE-LAB-2024-SEC01",
        evidence_observed="[+] Non-destructive probe returned HTTP 200 with directory listing capability. Exploitability verified without system disruption.",
        risk_assessment="High risk of arbitrary remote execution. Immediate patch deployment recommended.",
        remediation_status="Validated Vulnerable",
        verified_by="Senior Penetration Tester",
        execution_mode="controlled_simulation",
        created_at=datetime.utcnow() - timedelta(days=1)
    )
    db.add(msf_record)

    # 5. Initial Audit Logs
    audit1 = AuditLog(
        timestamp=datetime.utcnow() - timedelta(days=5),
        action="SYSTEM_INIT",
        actor="system",
        target_address="127.0.0.1",
        details="CyberShield VAPT Platform initialized. Database tables and security policies created.",
        status="SUCCESS"
    )
    audit2 = AuditLog(
        timestamp=datetime.utcnow() - timedelta(days=2),
        action="SCAN_STARTED",
        actor="sec-analyst",
        target_address="127.0.0.1",
        details="Standard Nmap network and service enumeration scan initiated.",
        status="SUCCESS"
    )
    audit3 = AuditLog(
        timestamp=datetime.utcnow() - timedelta(hours=8),
        action="REPORT_IMPORTED",
        actor="sec-analyst",
        target_address="192.168.56.102",
        details="Nessus CSV scan report successfully imported with 4 vulnerabilities.",
        status="SUCCESS"
    )
    db.add_all([audit1, audit2, audit3])
    db.commit()
