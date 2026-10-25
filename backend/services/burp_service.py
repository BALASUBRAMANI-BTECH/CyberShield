import os
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional

SAMPLE_BURP_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "sample_reports", "burp_sample_export.xml")
)


class BurpParserService:
    @classmethod
    def parse_xml(cls, xml_content: str, default_target_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """Parses Burp Suite XML issue export into standardized findings."""
        findings = []
        try:
            root = ET.fromstring(xml_content)
            # Burp XML structure: <issues burpVersion="..."><issue>...
            issues = root.findall(".//issue") if root.tag != "issue" else [root]

            for issue in issues:
                name_elem = issue.find("name")
                name = name_elem.text.strip() if name_elem is not None and name_elem.text else "Burp Security Issue"

                host_elem = issue.find("host")
                host = host_elem.text.strip() if host_elem is not None and host_elem.text else "localhost"

                path_elem = issue.find("path")
                path = path_elem.text.strip() if path_elem is not None and path_elem.text else "/"

                location_elem = issue.find("location")
                location = location_elem.text.strip() if location_elem is not None and location_elem.text else f"{host}{path}"

                severity_elem = issue.find("severity")
                sev_raw = severity_elem.text.strip() if severity_elem is not None and severity_elem.text else "Medium"

                confidence_elem = issue.find("confidence")
                conf = confidence_elem.text.strip() if confidence_elem is not None and confidence_elem.text else "Certain"

                detail_elem = issue.find("issueDetail")
                detail = detail_elem.text.strip() if detail_elem is not None and detail_elem.text else ""

                bg_elem = issue.find("issueBackground")
                bg = bg_elem.text.strip() if bg_elem is not None and bg_elem.text else "Burp Suite automated scanner alert."

                remed_elem = issue.find("remediationBackground")
                remediation = remed_elem.text.strip() if remed_elem is not None and remed_elem.text else "Inspect server code and apply standard defense controls."

                # Map severity
                sev_map = {"High": "High", "Medium": "Medium", "Low": "Low", "Information": "Info"}
                normalized_sev = sev_map.get(sev_raw, "Medium")
                cvss_map = {"High": 8.0, "Medium": 5.5, "Low": 3.5, "Info": 0.0}

                # Clean basic HTML tags from Burp output
                import re
                clean_desc = re.sub(r"<[^>]+>", "", f"{bg}\n\n{detail}").strip()
                clean_remed = re.sub(r"<[^>]+>", "", remediation).strip()

                findings.append({
                    "title": name,
                    "cve_id": None,
                    "cvss_score": cvss_map.get(normalized_sev, 5.0),
                    "severity": normalized_sev,
                    "detection_source": "Burp Suite",
                    "verification_status": "Verified / Confirmed" if conf.lower() == "certain" else "Unverified Automated",
                    "confidence": "High" if conf.lower() == "certain" else "Medium",
                    "affected_component": location,
                    "description": clean_desc,
                    "technical_impact": f"Reported by Burp Suite Scanner with confidence '{conf}'.",
                    "business_impact": "Application layer security degradation and potential exploitation of client/server logic.",
                    "remediation": clean_remed,
                    "raw_evidence": f"Burp Issue Location: {location}\nSeverity: {sev_raw}\nConfidence: {conf}",
                    "status": "Open"
                })
        except Exception as e:
            # Fallback or error logging
            print(f"Error parsing Burp XML: {e}")

        return findings

    @classmethod
    def load_sample_report(cls) -> str:
        if os.path.exists(SAMPLE_BURP_PATH):
            with open(SAMPLE_BURP_PATH, "r", encoding="utf-8") as f:
                return f.read()
        return """<?xml version="1.0"?>
<issues burpVersion="2023.12.1">
  <issue>
    <name>XML External Entity (XXE) Injection</name>
    <host ip="127.0.0.1">localhost</host>
    <path>/api/upload/xml</path>
    <location>http://localhost:3000/api/upload/xml</location>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueBackground>XML external entity injection occurs when XML input containing a reference to an external entity is processed by a weakly configured XML parser.</issueBackground>
    <remediationBackground>Disable DTDs (External Entities) completely in XML parsers.</remediationBackground>
    <issueDetail>The parser resolved system entity [file:///etc/passwd].</issueDetail>
  </issue>
</issues>"""
