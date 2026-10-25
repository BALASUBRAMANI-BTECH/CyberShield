# CyberShield VAPT - Vulnerability Assessment & Penetration Testing Platform

CyberShield VAPT is an enterprise-grade, full-stack Vulnerability Assessment and Penetration Testing management platform designed for security engineers, SOC analysts, and college final-year capstone portfolios. It empowers security practitioners to scan authorized lab targets, evaluate risks, catalog findings, conduct controlled proof-of-concept validations, and generate formal executive VAPT reports in PDF and CSV formats.

---

## 🛡️ Key Features

- **Executive Operations Dashboard:** Real-time CVSS telemetry, security health posture rating, threat meters, and interactive Recharts visualizations (severity donut, detections by scanner engine, recent scan feeds).
- **Target Asset Inventory & SSRF Protection:** Pre-execution allowlist validation restricting scans to loopback (`127.0.0.1`) and RFC 1918 private subnets. Live pre-check prevents Server-Side Request Forgery (SSRF) and blocks access to cloud metadata endpoints (`169.254.169.254`).
- **Nmap Network Enumeration:** Parameterized subprocess list execution (no shell concatenation), strict timeouts, port filtering, and banner grab detection.
- **OWASP ZAP Web Application DAST:** Real-time HTTP security header auditing (CSP, HSTS, X-Frame-Options), cookie security inspection (HttpOnly, Secure), and automated heuristic detection for OWASP Top 10 flaws (SQL Injection, XSS, CORS misconfigurations).
- **Tenable Nessus & Burp Suite Ingestion:** Native parsers for Nessus CSV exports and Burp Suite XML reports. Includes built-in realistic sample findings for offline demonstration.
- **Controlled Metasploit Validation:** Non-destructive lab validation workflow documenting preconditions, authorization proofs, observed technical evidence, and re-test tracking without arbitrary remote code execution risks.
- **Vulnerability Lifecycle Management:** Filterable finding catalog by Severity, Target, Status (Open, In Progress, Fixed, Accepted Risk), and Detection Engine with slide-out technical drawers.
- **Executive VAPT Report Generation:** Generates multi-page, executive-quality PDF reports (Cover page, Executive Summary, Scope & Authorization, Methodology, Target Inventory, Findings Matrix, Remediation Roadmap, and Sign-offs) using ReportLab, plus CSV exports.
- **Built-in Demo Simulation Mode:** Fully functional out-of-the-box even if Nmap, ZAP, Nessus, or Metasploit are not installed locally. Findings and scans are clearly watermarked as `[REAL SCANNER]`, `[IMPORTED REPORT]`, or `[DEMO SIMULATION]`.
- **Tamper-Evident Audit Logging:** Structured security event audit trail stored in SQLite tracking scan launches, target registrations, and remediation changes.

---

## 🛠️ Technology Stack

| Layer | Technology |
|---|---|
| **Frontend** | React 18, Vite, Tailwind CSS v3, Lucide React Icons |
| **Data Visualization** | Recharts (Responsive Pie & Bar Charts) |
| **Backend API** | Python 3.10+, FastAPI, Uvicorn, Pydantic v2 |
| **Database** | SQLite with SQLAlchemy 2.0 ORM |
| **Report Generation** | ReportLab 5.0 (PDF) & Python CSV Engine |
| **Testing** | Pytest, HTTPX TestClient |

---

## 📁 Project Structure

```
prj1/
├── backend/
│   ├── main.py                  # FastAPI application entrypoint & middleware
│   ├── models/
│   │   ├── database.py          # SQLAlchemy database engine & session maker
│   │   └── models.py            # Target, Scan, Vulnerability, Metasploit, Audit models
│   ├── schemas/
│   │   └── schemas.py           # Pydantic v2 validation models
│   ├── services/
│   │   ├── target_service.py    # Target validation, SSRF shield, allowlist policy
│   │   ├── nmap_service.py      # Nmap scanner integration & demo simulation
│   │   ├── zap_service.py       # OWASP ZAP DAST engine & live HTTP headers audit
│   │   ├── nessus_service.py    # Nessus CSV parser & sample report provider
│   │   ├── burp_service.py      # Burp Suite XML parser & sample report provider
│   │   ├── metasploit_service.py# Controlled non-destructive validation workflow
│   │   ├── report_service.py    # Multi-page ReportLab PDF generator & CSV exporter
│   │   └── seed_data.py         # Seed dataset with realistic lab targets & findings
│   └── routers/
│       ├── dashboard_router.py  # Telemetry metrics and statistics
│       ├── targets_router.py    # Target CRUD & SSRF pre-check
│       ├── scans_router.py      # Scan launcher & file import endpoints
│       ├── vulnerabilities_router.py # Finding filters & remediation updates
│       ├── metasploit_router.py # Controlled penetration testing validation
│       ├── reports_router.py    # PDF and CSV download endpoints
│       └── settings_router.py   # Tool health checks & audit logs
├── frontend/
│   ├── src/
│   │   ├── api.js               # API service client
│   │   ├── App.jsx              # Application state & routing coordinator
│   │   ├── components/          # Sidebar, Header, Badges, Toast
│   │   └── views/               # Dashboard, Targets, New Assessment, Scan Results,
│   │                            # Vulnerabilities, Metasploit, Reports, History, Settings
│   ├── tailwind.config.js       # Curated dark cyber theme tokens
│   └── package.json
├── data/
│   └── vapt.db                  # SQLite database (auto-initialized on startup)
├── sample_reports/
│   ├── nessus_sample_scan.csv   # Sample Nessus CSV export
│   ├── burp_sample_export.xml   # Sample Burp Suite XML export
│   └── example_vapt_report.pdf  # Generated reference VAPT report
├── tests/
│   └── test_vapt.py             # Pytest automated test suite
├── requirements.txt             # Python backend dependencies
└── .env.example                 # Environment configuration template
```

---

## 🚀 Installation & Getting Started

### Prerequisites
- **Python**: Version 3.10 or higher
- **Node.js**: Version 18 or higher (with npm)

### 1. Backend Setup
1. Clone or navigate to the project directory:
   ```bash
   cd c:\Users\balav\Documents\codeec\prj1
   ```
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Start the FastAPI backend server:
   ```bash
   python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
   ```
   *The backend will automatically create `data/vapt.db` and populate initial authorized lab targets and realistic findings.*
   *API documentation will be available at:* `http://127.0.0.1:8000/docs`

### 2. Frontend Setup
1. In a new terminal window, navigate to the `frontend` folder:
   ```bash
   cd frontend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start the Vite development server:
   ```bash
   npm run dev
   ```
4. Open your browser and navigate to:
   ```
   http://localhost:5173/
   ```

---

## 🔧 Integrating External Security Tools

The platform functions with rich simulation if external tools are absent, but you can connect real security tooling:

### 1. Nmap Network Scanner
- **Windows:** Download the Nmap installer from [nmap.org/download.html](https://nmap.org/download.html). Ensure "Add Nmap to PATH" is selected.
- **Verification:** Run `nmap --version` in terminal.
- **Usage:** Once installed, CyberShield automatically uses real Nmap subprocess calls (`["nmap", "-sV", ...]` with strict timeouts).

### 2. OWASP ZAP (Zed Attack Proxy)
- **Download:** Install OWASP ZAP from [zaproxy.org](https://www.zaproxy.org/download/).
- **Run in Daemon Mode:**
  ```bash
  zap.bat -daemon -port 8080 -config api.disablekey=true
  ```
- **Configuration:** Set `ZAP_API_URL=http://127.0.0.1:8080` in `.env`.

### 3. Tenable Nessus Ingestion
- In Tenable Nessus Web UI, navigate to any completed scan -> click **Export** -> select **CSV**.
- In CyberShield, go to **New Assessment** -> select **Nessus Report Ingestion** -> choose **Upload Export File** and submit.

### 4. Burp Suite Professional Ingestion
- In Burp Suite, select items in the Target or Issue activity list -> right-click -> select **Report issues** -> choose **XML format**.
- In CyberShield, go to **New Assessment** -> select **Burp Suite XML Ingestion** -> upload the `.xml` file.

### 5. Metasploit Framework Controlled Validation
- Metasploit validation is operated as a controlled non-destructive evidence workflow.
- Enter the authorization ticket reference (e.g. `ROE-LAB-2024`), verify preconditions, and execute auxiliary probes against authorized targets.

---

## 🧪 Running Automated Unit Tests

Execute the comprehensive Pytest suite:
```bash
python -m pytest tests/test_vapt.py -v
```

**Test Coverage:**
- `test_health_endpoint`: API availability & database status
- `test_dashboard_stats`: Real-time telemetry calculations
- `test_ssrf_protection_blocked_metadata`: Verification that cloud metadata IPs (`169.254.169.254`) are blocked
- `test_allowlist_enforcement`: Validation of loopback & RFC 1918 subnets
- `test_target_registration_ssrf_blocked`: Rejection of SSRF exploit payloads
- `test_nessus_csv_parser`: Ingestion of Nessus CSV columns, Plugin IDs, and CVEs
- `test_burp_xml_parser`: Parsing of Burp Suite XML issues
- `test_report_generation_csv_and_pdf`: Verification of ReportLab PDF generation and CSV RFC-4180 export
- `test_vulnerability_status_update`: State transition auditing

---

## 📸 Visual Verification Checklist

When presenting this application for final-year defense or portfolio review:
- [x] **Executive Dashboard:** Live metrics, security health score, threat level badge, Recharts severity distribution donut, and scanner tool breakdown bar chart.
- [x] **Target Allowlist Inventory:** 4 initial authorized lab targets (`127.0.0.1`, `OWASP Juice Shop`, `DVWA`, `Metasploitable 2`). Add Target modal with live SSRF pre-check.
- [x] **New Assessment Wizard:** Multi-step wizard supporting Nmap, OWASP ZAP, Full VAPT, Nessus, and Burp, with mandatory authorization confirmation.
- [x] **Terminal Console View:** Raw scanner output terminal emulator with copy-to-clipboard and parsed findings tab.
- [x] **Vulnerability Management:** Search filter, severity pills, status dropdowns, and slide-out detail drawer with CVSS, Technical Impact, Business Risk, and Remediation Roadmap.
- [x] **Controlled Metasploit Validation:** Preconditions audit, non-destructive probe evidence logging, and validation records.
- [x] **Report Center:** Live executive summary preview, download buttons for official multi-page PDF report and CSV spreadsheet.
- [x] **Settings & Security Health:** Real-time binary detection for all 5 tools, active CIDR allowlist display, and immutable security audit log table.
