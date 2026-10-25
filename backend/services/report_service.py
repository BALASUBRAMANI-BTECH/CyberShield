import csv
import html
import io
import os
from datetime import datetime
from typing import List, Dict, Any, Optional


def safe_xml(text: Optional[str]) -> str:
    """Safely escapes text for ReportLab platypus Paragraph XML parser."""
    if not text:
        return ""
    return html.escape(str(text))

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.units import inch


class ReportService:
    @classmethod
    def generate_csv(cls, findings: List[Any], scan_name: str = "Assessment") -> str:
        """Generates RFC-4180 compliant CSV string of vulnerability findings."""
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_ALL)

        headers = [
            "Finding ID",
            "Vulnerability Title",
            "Severity",
            "CVSS Base Score",
            "CVE Identifier",
            "Target Asset",
            "Affected Component",
            "Detection Source",
            "Verification Status",
            "Remediation Status",
            "Technical Impact",
            "Business Impact",
            "Remediation Steps",
            "Raw Evidence Snippet",
            "Identified Date"
        ]
        writer.writerow(headers)

        for f in findings:
            created_str = f.created_at.strftime("%Y-%m-%d %H:%M:%S") if hasattr(f, "created_at") and f.created_at else ""
            target_addr = "N/A"
            try:
                if hasattr(f, "target") and f.target:
                    target_addr = f.target.address
            except Exception:
                target_addr = getattr(f, "affected_component", "N/A")
            writer.writerow([
                getattr(f, "finding_uid", f"FIND-{f.id}"),
                f.title,
                f.severity,
                f.cvss_score if f.cvss_score is not None else "",
                f.cve_id or "",
                target_addr,
                f.affected_component or "",
                f.detection_source,
                f.verification_status,
                f.status,
                f.technical_impact or "",
                f.business_impact or "",
                f.remediation or "",
                (f.raw_evidence or "")[:250].replace("\n", " "),
                created_str
            ])

        return output.getvalue()

    @classmethod
    def generate_pdf(
        cls,
        findings: List[Any],
        target_info: Optional[Any] = None,
        scan_info: Optional[Any] = None,
        executive_summary: Optional[str] = None
    ) -> bytes:
        """
        Generates a comprehensive executive-grade VAPT PDF report using ReportLab.
        Sections: Cover Page, Executive Summary, Scope & Authorization, Methodology,
        Tools Used, Target Inventory, Vulnerability Severity Matrix, Detailed Findings,
        Remediation Roadmap, Conclusion.
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()

        # Custom cybersecurity styles
        title_style = ParagraphStyle(
            'CoverTitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=28,
            leading=34,
            textColor=colors.HexColor('#0B1320'),
            alignment=1, # Center
            spaceAfter=15
        )

        subtitle_style = ParagraphStyle(
            'CoverSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=15,
            leading=20,
            textColor=colors.HexColor('#0891B2'),
            alignment=1,
            spaceAfter=30
        )

        meta_style = ParagraphStyle(
            'CoverMeta',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            leading=16,
            textColor=colors.HexColor('#475569'),
            alignment=1
        )

        h1_style = ParagraphStyle(
            'SectionH1',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=18,
            leading=24,
            textColor=colors.HexColor('#0F172A'),
            spaceBefore=14,
            spaceAfter=8
        )

        h2_style = ParagraphStyle(
            'SectionH2',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=13,
            leading=18,
            textColor=colors.HexColor('#0369A1'),
            spaceBefore=10,
            spaceAfter=4
        )

        body_style = ParagraphStyle(
            'ReportBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9.5,
            leading=14,
            textColor=colors.HexColor('#1E293B'),
            spaceAfter=8
        )

        code_style = ParagraphStyle(
            'ReportCode',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=8,
            leading=11,
            textColor=colors.HexColor('#0F172A'),
            backColor=colors.HexColor('#F1F5F9'),
            borderPadding=6,
            spaceAfter=8
        )

        story = []

        # ----------------- COVER PAGE -----------------
        story.append(Spacer(1, 1.2 * inch))
        story.append(Paragraph("CYBERSHIELD VAPT PLATFORM", ParagraphStyle(
            'Kicker', fontName='Helvetica-Bold', fontSize=12, leading=16, textColor=colors.HexColor('#0284C7'), alignment=1, spaceAfter=15
        )))
        story.append(Paragraph("Vulnerability Assessment & Penetration Testing Report", title_style))
        story.append(Paragraph("COMPREHENSIVE SECURITY AUDIT & RISK ANALYSIS", subtitle_style))
        story.append(Spacer(1, 0.4 * inch))

        target_name = safe_xml(target_info.name if target_info else "Enterprise Security Environment")
        target_addr = safe_xml(target_info.address if target_info else "Multi-Asset Scope")
        scan_title = safe_xml(scan_info.scan_name if scan_info else "Comprehensive Multi-Vector Assessment")

        summary_box_data = [
            [Paragraph("<b>Target Environment:</b>", body_style), Paragraph(f"{target_name} ({target_addr})", body_style)],
            [Paragraph("<b>Assessment Type:</b>", body_style), Paragraph(scan_title, body_style)],
            [Paragraph("<b>Audit Date:</b>", body_style), Paragraph(datetime.utcnow().strftime("%B %d, %Y"), body_style)],
            [Paragraph("<b>Classification:</b>", body_style), Paragraph("<font color='#DC2626'><b>CONFIDENTIAL - RESTRICTED DISTRIBUTION</b></font>", body_style)],
            [Paragraph("<b>Prepared By:</b>", body_style), Paragraph("CyberShield Automated Security Operations Center", body_style)],
            [Paragraph("<b>Standard / Framework:</b>", body_style), Paragraph("OWASP Top 10 / NIST SP 800-115 / PTES", body_style)],
        ]
        t_cover = Table(summary_box_data, colWidths=[2.2 * inch, 4.8 * inch])
        t_cover.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
            ('BOX', (0, 0), (-1, -1), 1.5, colors.HexColor('#CBD5E1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 7),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ]))
        story.append(t_cover)

        story.append(Spacer(1, 1.2 * inch))
        story.append(Paragraph("Document Version 1.0 &bull; Generated Automatically by CyberShield VAPT Engine", meta_style))
        story.append(PageBreak())

        # ----------------- SECTION 1: EXECUTIVE SUMMARY -----------------
        story.append(Paragraph("1. Executive Summary", h1_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284C7'), spaceBefore=2, spaceAfter=8))

        # Severity metrics calculation
        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in findings:
            s = f.severity if f.severity in sev_counts else "Medium"
            sev_counts[s] += 1

        total_findings = len(findings)

        exec_text = executive_summary or (
            f"During this assessment, CyberShield evaluated target assets for technical and architectural vulnerabilities. "
            f"A total of <b>{total_findings} security findings</b> were identified across the specified scope, comprising "
            f"<b>{sev_counts['Critical']} Critical</b>, <b>{sev_counts['High']} High</b>, <b>{sev_counts['Medium']} Medium</b>, "
            f"<b>{sev_counts['Low']} Low</b>, and <b>{sev_counts['Info']} Informational</b> risks. "
            f"Vulnerabilities rated as Critical or High represent immediate vectors that could permit unauthorized access, "
            f"remote code execution, or credential theft, and should be prioritized for urgent remediation."
        )
        story.append(Paragraph(exec_text, body_style))
        story.append(Spacer(1, 10))

        # Executive Metrics Table
        metrics_table_data = [
            [
                Paragraph("<b>Critical</b>", ParagraphStyle('M1', textColor=colors.HexColor('#991B1B'), fontName='Helvetica-Bold', alignment=1)),
                Paragraph("<b>High</b>", ParagraphStyle('M2', textColor=colors.HexColor('#C2410C'), fontName='Helvetica-Bold', alignment=1)),
                Paragraph("<b>Medium</b>", ParagraphStyle('M3', textColor=colors.HexColor('#B45309'), fontName='Helvetica-Bold', alignment=1)),
                Paragraph("<b>Low</b>", ParagraphStyle('M4', textColor=colors.HexColor('#1D4ED8'), fontName='Helvetica-Bold', alignment=1)),
                Paragraph("<b>Info</b>", ParagraphStyle('M5', textColor=colors.HexColor('#047857'), fontName='Helvetica-Bold', alignment=1)),
                Paragraph("<b>Total Findings</b>", ParagraphStyle('M6', textColor=colors.HexColor('#0F172A'), fontName='Helvetica-Bold', alignment=1))
            ],
            [
                Paragraph(f"<font size=15><b>{sev_counts['Critical']}</b></font>", ParagraphStyle('N1', alignment=1)),
                Paragraph(f"<font size=15><b>{sev_counts['High']}</b></font>", ParagraphStyle('N2', alignment=1)),
                Paragraph(f"<font size=15><b>{sev_counts['Medium']}</b></font>", ParagraphStyle('N3', alignment=1)),
                Paragraph(f"<font size=15><b>{sev_counts['Low']}</b></font>", ParagraphStyle('N4', alignment=1)),
                Paragraph(f"<font size=15><b>{sev_counts['Info']}</b></font>", ParagraphStyle('N5', alignment=1)),
                Paragraph(f"<font size=15><b>{total_findings}</b></font>", ParagraphStyle('N6', alignment=1))
            ]
        ]
        t_metrics = Table(metrics_table_data, colWidths=[1.16 * inch] * 6)
        t_metrics.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#FEE2E2')),
            ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#FFEDD5')),
            ('BACKGROUND', (2, 0), (2, -1), colors.HexColor('#FEF3C7')),
            ('BACKGROUND', (3, 0), (3, -1), colors.HexColor('#DBEAFE')),
            ('BACKGROUND', (4, 0), (4, -1), colors.HexColor('#D1FAE5')),
            ('BACKGROUND', (5, 0), (5, -1), colors.HexColor('#F1F5F9')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#CBD5E1')),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(t_metrics)
        story.append(Spacer(1, 15))

        # ----------------- SECTION 2: SCOPE & METHODOLOGY -----------------
        story.append(Paragraph("2. Assessment Scope & Rules of Engagement", h1_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284C7'), spaceBefore=2, spaceAfter=8))
        scope_text = (
            "All assessment activities were conducted strictly against authorized lab targets in compliance with explicit "
            "allowlisting controls. Testing methodologies incorporated automated port and service enumeration, "
            "application-layer vulnerability scanning, security header validation, and controlled non-destructive evidence verification."
        )
        story.append(Paragraph(scope_text, body_style))

        # Target Inventory Table
        target_table_data = [
            [
                Paragraph("<b>Asset Name</b>", body_style),
                Paragraph("<b>Target Address / URL</b>", body_style),
                Paragraph("<b>Target Type</b>", body_style),
                Paragraph("<b>Authorization Status</b>", body_style),
            ],
            [
                Paragraph(target_name, body_style),
                Paragraph(target_addr, body_style),
                Paragraph(getattr(target_info, "target_type", "Lab Host").upper(), body_style),
                Paragraph("<font color='#059669'><b>Authorized Lab Scope</b></font>", body_style),
            ]
        ]
        t_targets = Table(target_table_data, colWidths=[2.2 * inch, 2.5 * inch, 1.1 * inch, 1.2 * inch])
        t_targets.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E2E8F0')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(t_targets)
        story.append(Spacer(1, 15))

        # ----------------- SECTION 3: TOOLS UTILIZED -----------------
        story.append(Paragraph("3. Security Tooling & Architecture", h1_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284C7'), spaceBefore=2, spaceAfter=8))
        tools_data = [
            [Paragraph("<b>Tool</b>", body_style), Paragraph("<b>Category</b>", body_style), Paragraph("<b>Function / Purpose</b>", body_style)],
            [Paragraph("Nmap 7.94", body_style), Paragraph("Network Scanner", body_style), Paragraph("Port discovery, OS fingerprinting, and service version identification.", body_style)],
            [Paragraph("OWASP ZAP 2.14", body_style), Paragraph("DAST Scanner", body_style), Paragraph("Automated web application vulnerability auditing and HTTP header inspection.", body_style)],
            [Paragraph("Nessus Professional", body_style), Paragraph("Vulnerability Scanner", body_style), Paragraph("Enterprise CVE auditing and configuration compliance assessment.", body_style)],
            [Paragraph("Burp Suite Professional", body_style), Paragraph("Web Proxy / Scanner", body_style), Paragraph("Deep-layer manual and automated web flaw detection.", body_style)],
            [Paragraph("Metasploit Framework", body_style), Paragraph("Penetration Testing", body_style), Paragraph("Controlled validation and proof-of-concept evidence verification.", body_style)]
        ]
        t_tools = Table(tools_data, colWidths=[1.8 * inch, 1.6 * inch, 3.6 * inch])
        t_tools.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E2E8F0')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(t_tools)

        story.append(PageBreak())

        # ----------------- SECTION 4: DETAILED FINDINGS -----------------
        story.append(Paragraph("4. Detailed Technical Findings & Remediation", h1_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284C7'), spaceBefore=2, spaceAfter=10))

        if not findings:
            story.append(Paragraph("No vulnerabilities were identified during this assessment.", body_style))
        else:
            for i, f in enumerate(findings, 1):
                sev_color_map = {
                    "Critical": "#991B1B",
                    "High": "#C2410C",
                    "Medium": "#B45309",
                    "Low": "#1D4ED8",
                    "Info": "#047857"
                }
                sev_bg_map = {
                    "Critical": "#FEE2E2",
                    "High": "#FFEDD5",
                    "Medium": "#FEF3C7",
                    "Low": "#DBEAFE",
                    "Info": "#D1FAE5"
                }
                scolor = sev_color_map.get(f.severity, "#1E293B")
                sbg = sev_bg_map.get(f.severity, "#F1F5F9")

                uid = safe_xml(getattr(f, 'finding_uid', f'VAPT-{i:03d}'))
                finding_header = [
                    [
                        Paragraph(f"<b>#{i} &bull; {uid}: {safe_xml(f.title)}</b>", ParagraphStyle('FTitle', fontName='Helvetica-Bold', fontSize=10.5, textColor=colors.HexColor(scolor))),
                        Paragraph(f"<b>{safe_xml(f.severity.upper())}</b> (CVSS: {f.cvss_score or 'N/A'})", ParagraphStyle('FSeverity', fontName='Helvetica-Bold', fontSize=10, textColor=colors.HexColor(scolor), alignment=2))
                    ]
                ]
                t_fhead = Table(finding_header, colWidths=[5.2 * inch, 1.8 * inch])
                t_fhead.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor(sbg)),
                    ('BOX', (0, 0), (-1, -1), 1, colors.HexColor(scolor)),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LEFTPADDING', (0, 0), (-1, -1), 8),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                ]))

                meta_rows = [
                    [Paragraph("<b>Detection Source:</b>", body_style), Paragraph(safe_xml(f.detection_source), body_style), Paragraph("<b>Status:</b>", body_style), Paragraph(safe_xml(f.status), body_style)],
                    [Paragraph("<b>Affected Asset:</b>", body_style), Paragraph(safe_xml(f.affected_component or "N/A"), body_style), Paragraph("<b>Verification:</b>", body_style), Paragraph(safe_xml(f.verification_status), body_style)],
                ]
                if f.cve_id:
                    meta_rows.append([Paragraph("<b>CVE Identifier:</b>", body_style), Paragraph(safe_xml(f.cve_id), body_style), Paragraph("", body_style), Paragraph("", body_style)])

                t_fmeta = Table(meta_rows, colWidths=[1.5 * inch, 2.5 * inch, 1.2 * inch, 1.8 * inch])
                t_fmeta.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
                    ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
                    ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ]))

                finding_elements = [
                    t_fhead,
                    t_fmeta,
                    Spacer(1, 4),
                    Paragraph("<b>Description:</b>", h2_style),
                    Paragraph(safe_xml(f.description), body_style),
                ]

                if f.technical_impact:
                    finding_elements.extend([
                        Paragraph("<b>Technical Impact:</b>", h2_style),
                        Paragraph(safe_xml(f.technical_impact), body_style),
                    ])

                if f.business_impact:
                    finding_elements.extend([
                        Paragraph("<b>Business Risk:</b>", h2_style),
                        Paragraph(safe_xml(f.business_impact), body_style),
                    ])

                if f.remediation:
                    finding_elements.extend([
                        Paragraph("<b>Remediation Roadmap:</b>", h2_style),
                        Paragraph(safe_xml(f.remediation), body_style),
                    ])

                if f.raw_evidence:
                    finding_elements.extend([
                        Paragraph("<b>Observed Evidence / POC Output:</b>", h2_style),
                        Paragraph(safe_xml(f.raw_evidence[:600]), code_style),
                    ])

                finding_elements.append(Spacer(1, 14))
                story.append(KeepTogether(finding_elements))

        # ----------------- SECTION 5: CONCLUSION & SIGN-OFF -----------------
        story.append(PageBreak())
        story.append(Paragraph("5. Conclusion & Strategic Guidance", h1_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284C7'), spaceBefore=2, spaceAfter=8))
        conclusion_text = (
            "The assessed infrastructure demonstrates baseline operational functionality; however, the presence of Critical and "
            "High severity findings requires immediate and disciplined mitigation. We advise development and operations teams "
            "to establish a 14-day remediation cadence for Critical CVEs and unauthenticated flaws, followed by a full re-test cycle "
            "to confirm vulnerability closure."
        )
        story.append(Paragraph(conclusion_text, body_style))
        story.append(Spacer(1, 20))

        # Sign-off box
        sign_data = [
            [Paragraph("<b>Lead Security Assessor</b>", body_style), Paragraph("<b>Cybersecurity Operations Director</b>", body_style)],
            [Paragraph("<br/><br/>_____________________________________<br/>CyberShield SecOps Lead", body_style),
             Paragraph("<br/><br/>_____________________________________<br/>Head of Information Security", body_style)],
        ]
        t_sign = Table(sign_data, colWidths=[3.5 * inch, 3.5 * inch])
        t_sign.setStyle(TableStyle([
            ('LINEABOVE', (0, 0), (-1, 0), 1, colors.HexColor('#CBD5E1')),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
        ]))
        story.append(t_sign)

        # Build document
        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes
