import shutil
import subprocess
import time
from typing import Dict, Any, List
from backend.services.target_service import TargetSecurityService


class NmapScannerService:
    @staticmethod
    def is_nmap_installed() -> bool:
        return shutil.which("nmap") is not None

    @classmethod
    def get_tool_status(cls) -> Dict[str, Any]:
        installed = cls.is_nmap_installed()
        version_str = "Not installed in PATH"
        if installed:
            try:
                res = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=5)
                first_line = res.stdout.strip().split("\n")[0]
                version_str = first_line
            except Exception as e:
                version_str = f"Installed (error probing version: {str(e)})"
        return {
            "name": "Nmap Network Scanner",
            "installed": installed,
            "version": version_str,
            "binary_path": shutil.which("nmap") or "None",
            "features": ["Host Discovery", "Port Scanning", "Service Version Detection", "NSE Script Scanning"]
        }

    @classmethod
    def execute_scan(cls, target_address: str, profile: str = "standard", ports: str = None, force_demo: bool = False) -> Dict[str, Any]:
        """
        Executes Nmap scan using safe subprocess list or realistic demo adapter.
        """
        # Validate target host
        host = TargetSecurityService.extract_host(target_address)
        nmap_available = cls.is_nmap_installed() and not force_demo

        if nmap_available:
            return cls._run_real_nmap(host, profile, ports)
        else:
            return cls._run_demo_nmap(host, profile, ports)

    @classmethod
    def _run_real_nmap(cls, host: str, profile: str, ports: str = None) -> Dict[str, Any]:
        start_time = time.time()
        # Safe argument construction
        args = ["nmap"]

        if profile == "quick":
            args.extend(["-T4", "-F", "--open"])
        elif profile == "intense":
            args.extend(["-T4", "-sV", "-sC", "--version-intensity", "5", "--open"])
        else:  # standard
            args.extend(["-T4", "-sV", "--open"])

        if ports:
            # Clean ports: only numbers, commas, dashes
            safe_ports = "".join(c for c in ports if c.isdigit() or c in ",-")
            if safe_ports:
                args.extend(["-p", safe_ports])

        args.append(host)

        try:
            # Enforce 120s timeout and NO shell=True
            result = subprocess.run(args, capture_output=True, text=True, timeout=120)
            elapsed = round(time.time() - start_time, 2)
            raw_output = result.stdout
            if result.stderr:
                raw_output += f"\n[Scanner Warnings/Errors]:\n{result.stderr}"

            findings = cls._parse_nmap_output(raw_output, host)

            return {
                "success": True,
                "execution_source": "real_tool",
                "is_demo": False,
                "duration_seconds": elapsed,
                "raw_output": raw_output,
                "findings": findings
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "execution_source": "real_tool",
                "is_demo": False,
                "duration_seconds": 120,
                "raw_output": f"[ERROR] Nmap execution timed out after 120 seconds on host {host}.",
                "findings": []
            }
        except Exception as e:
            return {
                "success": False,
                "execution_source": "real_tool",
                "is_demo": False,
                "duration_seconds": round(time.time() - start_time, 2),
                "raw_output": f"[ERROR] Failed to execute Nmap: {str(e)}",
                "findings": []
            }

    @classmethod
    def _run_demo_nmap(cls, host: str, profile: str, ports: str = None) -> Dict[str, Any]:
        """Provides realistic Nmap output simulation with clear labeling."""
        time.sleep(1.2)  # Realistic scan progression feel

        is_web_lab = "3000" in host or "juice" in host.lower() or "dvwa" in host.lower()

        if is_web_lab or host in ("127.0.0.1", "localhost"):
            raw_output = f"""Starting Nmap 7.94 ( https://nmap.org ) at 2026-10-25 08:40 UTC
Nmap scan report for {host}
Host is up (0.00042s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http        Apache httpd 2.4.49 ((Debian) OpenSSL/1.1.1n)
|_http-server-header: Apache/2.4.49 (Debian)
|_http-title: Lab Security Evaluation Environment
3000/tcp open  http        Node.js Express framework
|_http-title: OWASP Juice Shop
3306/tcp open  mysql       MySQL 5.7.34-0ubuntu0.18.04.1
| mysql-info: 
|_  Protocol: 10
8080/tcp open  http-proxy  Apache Tomcat 9.0.41
|_http-title: Administration Portal Login

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2.38 seconds
[NOTE: Simulated scan completed via CyberShield Demo Adapter - Nmap executable not installed in environment]"""
            
            findings = [
                {
                    "title": "Apache HTTP Server 2.4.49 Remote Code Execution & Path Traversal",
                    "cve_id": "CVE-2021-41773",
                    "cvss_score": 9.8,
                    "severity": "Critical",
                    "detection_source": "Nmap",
                    "verification_status": "Simulated Finding",
                    "confidence": "High",
                    "affected_component": f"Port 80/tcp (Apache 2.4.49)",
                    "description": "Nmap version detection identified Apache HTTP Server 2.4.49. A flaw in URI path normalization in Apache HTTP Server 2.4.49 allows an attacker to map URLs to files outside the expected document root (Path Traversal) and execute CGI scripts remotely.",
                    "technical_impact": "Full unauthenticated arbitrary code execution and reading of sensitive files such as /etc/passwd.",
                    "business_impact": "Severe breach of host confidentiality, integrity, and risk of lateral network compromise.",
                    "remediation": "Immediately upgrade Apache HTTP Server to version 2.4.51 or higher, or disable CGI and directory path aliases.",
                    "raw_evidence": "PORT 80/tcp open http Apache httpd 2.4.49 ((Debian) OpenSSL/1.1.1n)\nServer banner: Apache/2.4.49",
                    "status": "Open"
                },
                {
                    "title": "MySQL Database Port Exposed Without Network Restriction",
                    "cve_id": None,
                    "cvss_score": 6.5,
                    "severity": "Medium",
                    "detection_source": "Nmap",
                    "verification_status": "Simulated Finding",
                    "confidence": "High",
                    "affected_component": f"Port 3306/tcp (MySQL 5.7.34)",
                    "description": "MySQL database listener port 3306 is open and directly accessible across the network boundary, increasing brute-force and remote exploitation surface.",
                    "technical_impact": "Direct unauthorized database brute force, credential spraying, and protocol exploitation.",
                    "business_impact": "Unauthorized disclosure of stored customer or transactional databases.",
                    "remediation": "Bind MySQL service to localhost (bind-address = 127.0.0.1) or restrict access strictly using firewall allowlists.",
                    "raw_evidence": "PORT 3306/tcp open mysql MySQL 5.7.34-0ubuntu0.18.04.1",
                    "status": "Open"
                },
                {
                    "title": "Outdated Apache Tomcat Service Discovered",
                    "cve_id": "CVE-2020-13935",
                    "cvss_score": 7.5,
                    "severity": "High",
                    "detection_source": "Nmap",
                    "verification_status": "Simulated Finding",
                    "confidence": "Medium",
                    "affected_component": f"Port 8080/tcp (Tomcat 9.0.41)",
                    "description": "Apache Tomcat 9.0.41 was identified on port 8080. This version is vulnerable to remote Denial of Service (DoS) attacks via WebSocket payload handling flaws.",
                    "technical_impact": "Server resource exhaustion leading to total application unavailability.",
                    "business_impact": "Application downtime, violation of operational SLAs, and administrative disruption.",
                    "remediation": "Upgrade Apache Tomcat to the latest stable branch (9.0.80+ or 10.1+).",
                    "raw_evidence": "PORT 8080/tcp open http-proxy Apache Tomcat 9.0.41",
                    "status": "Open"
                }
            ]
        else:
            raw_output = f"""Starting Nmap 7.94 ( https://nmap.org ) at 2026-10-25 08:40 UTC
Nmap scan report for {host}
Host is up (0.0012s latency).
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp  open  http    nginx 1.18.0
443/tcp open  ssl/http nginx 1.18.0
Nmap done: 1 IP address (1 host up) scanned in 1.45 seconds
[NOTE: Simulated scan completed via CyberShield Demo Adapter]"""
            findings = [
                {
                    "title": "Nginx Web Server Information Disclosure via Version Banner",
                    "cve_id": None,
                    "cvss_score": 3.1,
                    "severity": "Low",
                    "detection_source": "Nmap",
                    "verification_status": "Simulated Finding",
                    "confidence": "High",
                    "affected_component": f"Port 80/tcp (nginx 1.18.0)",
                    "description": "The web server reveals its precise product name and version number in the Server header and default error pages.",
                    "technical_impact": "Assists attackers in targeting version-specific vulnerabilities.",
                    "business_impact": "Minimal direct impact; lowers the barrier for targeted reconnaissance.",
                    "remediation": "Set 'server_tokens off;' inside nginx.conf configuration file.",
                    "raw_evidence": "PORT 80/tcp open http nginx 1.18.0",
                    "status": "Open"
                }
            ]

        return {
            "success": True,
            "execution_source": "demo_simulation",
            "is_demo": True,
            "duration_seconds": 2.38,
            "raw_output": raw_output,
            "findings": findings
        }

    @classmethod
    def _parse_nmap_output(cls, raw_output: str, host: str) -> List[Dict[str, Any]]:
        """Parses real Nmap terminal text to extract open ports and construct findings."""
        findings = []
        lines = raw_output.split("\n")
        in_ports_section = False

        for line in lines:
            line_str = line.strip()
            if line_str.startswith("PORT") and "STATE" in line_str:
                in_ports_section = True
                continue
            if in_ports_section:
                if not line_str or line_str.startswith("Nmap done") or line_str.startswith("Service detection"):
                    break
                parts = line_str.split()
                if len(parts) >= 3 and "/tcp" in parts[0] or "/udp" in parts[0]:
                    port_proto = parts[0]
                    state = parts[1]
                    service = parts[2]
                    version = " ".join(parts[3:]) if len(parts) > 3 else "unknown"

                    if state.lower() == "open":
                        severity = "Low"
                        if "ftp" in service.lower() or "telnet" in service.lower():
                            severity = "Medium"
                        elif "smb" in service.lower() or "ms-wbt" in service.lower() or "445" in port_proto:
                            severity = "Medium"

                        findings.append({
                            "title": f"Open Service Detected: {service.upper()} on {port_proto}",
                            "cve_id": None,
                            "cvss_score": 4.0 if severity == "Low" else 5.3,
                            "severity": severity,
                            "detection_source": "Nmap",
                            "verification_status": "Unverified Automated",
                            "confidence": "High",
                            "affected_component": f"{port_proto} ({service} - {version})",
                            "description": f"Port {port_proto} was found OPEN running service '{service}' (Version: {version}). Open ports increase attack surface and require explicit hardening.",
                            "technical_impact": f"Attack surface exposure for service {service}.",
                            "business_impact": "Potential entry vector if service credentials or software are unpatched.",
                            "remediation": f"Verify if {service} on port {port_proto} is required. If not, disable or filter via firewall.",
                            "raw_evidence": line_str,
                            "status": "Open"
                        })

        return findings
