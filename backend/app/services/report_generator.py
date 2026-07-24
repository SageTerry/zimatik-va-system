"""PDF technical assessment report generation for VACE findings.

``ReportGenerator`` turns a list of findings plus a small metadata dict into
a client-ready PDF: a dark title block, an executive summary with severity
counts, a findings table grouped by severity, a full technical write-up for
every Critical/High finding (description, evidence, CVSS, remediation,
references, location), and an appendix of affected systems and scan
metadata.

It only reads attributes off the objects it's given (``title``, ``cve_id``,
``severity_normalized``, ...) - it doesn't touch the database itself, so it
can be called with real ORM ``Finding`` rows from an API endpoint, or with
hand-built objects in a test, equally well.
"""

from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from typing import Any, Dict, List, Optional, Sequence

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# --- Visual language: mirrors the frontend's dark theme + severity colors ---
# (see frontend/src/lib/constants.js - SEVERITY_STYLES[*].chart)

DARK_BG = colors.HexColor("#111827")  # gray-900, same as the app shell
BORDER = colors.HexColor("#374151")  # gray-700
TEXT_MUTED = colors.HexColor("#6b7280")  # gray-500
TEXT_BODY = colors.HexColor("#1f2937")  # gray-800
ROW_ALT = colors.HexColor("#f9fafb")  # gray-50

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#ef4444"),
    "HIGH": colors.HexColor("#f97316"),
    "MEDIUM": colors.HexColor("#eab308"),
    "LOW": colors.HexColor("#3b82f6"),
    "INFO": colors.HexColor("#6b7280"),
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
DETAIL_SEVERITIES = {"CRITICAL", "HIGH"}

PAGE_WIDTH, PAGE_HEIGHT = letter
CONTENT_WIDTH = PAGE_WIDTH - 1.2 * inch  # matches 0.6in left/right margins


class ReportGenerator:
    """Renders a VACE technical assessment report as PDF bytes."""

    def __init__(self) -> None:
        self.styles = self._build_styles()

    # --- Public API -----------------------------------------------------------

    def generate_technical_report(
        self, findings: Sequence[Any], scan_metadata: Dict[str, Any]
    ) -> bytes:
        """Render ``findings`` into a full technical report, returned as PDF bytes.

        ``scan_metadata`` is a small dict describing where the findings came
        from: ``{"scope": str, "scans": [{"name", "scope", "status",
        "started_at", "completed_at"}, ...], "generated_at": datetime}``. All
        keys are optional - missing ones just render as "not provided".
        """
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            topMargin=0.6 * inch,
            bottomMargin=0.85 * inch,
            leftMargin=0.6 * inch,
            rightMargin=0.6 * inch,
            title="VACE Technical Assessment Report",
        )

        findings = list(findings)
        story: List[Any] = []
        story += self._build_title_block(scan_metadata)
        story += self._build_executive_summary(findings)
        story.append(PageBreak())
        story += self._build_findings_table(findings)
        story.append(PageBreak())
        story += self._build_detailed_findings(findings)
        story.append(PageBreak())
        story += self._build_appendix(findings, scan_metadata)

        doc.build(story, onFirstPage=self._draw_footer, onLaterPages=self._draw_footer)
        return buffer.getvalue()

    # --- Styles -----------------------------------------------------------------

    @staticmethod
    def _build_styles() -> Dict[str, ParagraphStyle]:
        base = getSampleStyleSheet()
        return {
            "ReportTitle": ParagraphStyle(
                "ReportTitle",
                parent=base["Title"],
                fontName="Helvetica-Bold",
                fontSize=22,
                leading=26,
                textColor=colors.white,
                alignment=0,
                spaceAfter=4,
            ),
            "ReportSubtitle": ParagraphStyle(
                "ReportSubtitle",
                parent=base["Normal"],
                fontName="Helvetica",
                fontSize=10,
                leading=15,
                textColor=colors.HexColor("#d1d5db"),
            ),
            "SectionHeading": ParagraphStyle(
                "SectionHeading",
                parent=base["Heading1"],
                fontName="Helvetica-Bold",
                fontSize=15,
                textColor=DARK_BG,
                spaceBefore=0,
                spaceAfter=12,
            ),
            "FindingHeading": ParagraphStyle(
                "FindingHeading",
                parent=base["Heading2"],
                fontName="Helvetica-Bold",
                fontSize=12.5,
                leading=15,
                textColor=DARK_BG,
                spaceBefore=0,
                spaceAfter=0,
            ),
            "SubHeading": ParagraphStyle(
                "SubHeading",
                parent=base["Heading3"],
                fontName="Helvetica-Bold",
                fontSize=9,
                textColor=TEXT_MUTED,
                spaceBefore=8,
                spaceAfter=3,
            ),
            "Body": ParagraphStyle(
                "Body",
                parent=base["Normal"],
                fontName="Helvetica",
                fontSize=9.5,
                leading=13.5,
                textColor=TEXT_BODY,
            ),
            "Meta": ParagraphStyle(
                "Meta",
                parent=base["Normal"],
                fontName="Helvetica",
                fontSize=8.5,
                leading=12,
                textColor=TEXT_MUTED,
            ),
            "Mono": ParagraphStyle(
                "Mono",
                parent=base["Normal"],
                fontName="Courier",
                fontSize=8.2,
                leading=11.5,
                textColor=DARK_BG,
                backColor=colors.HexColor("#f3f4f6"),
                borderPadding=6,
            ),
            "TableCell": ParagraphStyle(
                "TableCell",
                parent=base["Normal"],
                fontName="Helvetica",
                fontSize=8.5,
                leading=11,
                textColor=TEXT_BODY,
            ),
            "TableHeader": ParagraphStyle(
                "TableHeader",
                parent=base["Normal"],
                fontName="Helvetica-Bold",
                fontSize=8.5,
                leading=11,
                textColor=colors.white,
            ),
            "GroupHeader": ParagraphStyle(
                "GroupHeader",
                parent=base["Normal"],
                fontName="Helvetica-Bold",
                fontSize=10,
                leading=13,
                textColor=colors.white,
            ),
        }

    # --- Section: title block ---------------------------------------------------

    def _build_title_block(self, scan_metadata: Dict[str, Any]) -> List[Any]:
        generated_at = scan_metadata.get("generated_at") or datetime.now(timezone.utc)
        scope = scan_metadata.get("scope") or "All assessed assets"

        header = Table(
            [
                [Paragraph("VACE Technical Assessment Report", self.styles["ReportTitle"])],
                [
                    Paragraph(
                        f"Scope: {self._escape(scope)}<br/>"
                        f"Generated: {self._fmt_dt(generated_at)}",
                        self.styles["ReportSubtitle"],
                    )
                ],
            ],
            colWidths=[CONTENT_WIDTH],
        )
        header.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), DARK_BG),
                    ("TOPPADDING", (0, 0), (-1, 0), 22),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 2),
                    ("TOPPADDING", (0, 1), (-1, 1), 2),
                    ("BOTTOMPADDING", (0, 1), (-1, 1), 22),
                    ("LEFTPADDING", (0, 0), (-1, -1), 24),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 24),
                ]
            )
        )
        return [header, Spacer(1, 22)]

    # --- Section: executive summary ---------------------------------------------

    def _build_executive_summary(self, findings: List[Any]) -> List[Any]:
        story: List[Any] = [Paragraph("Executive Summary", self.styles["SectionHeading"])]

        total = len(findings)
        counts = {sev: 0 for sev in SEVERITY_ORDER}
        for f in findings:
            counts[self._severity(f)] = counts.get(self._severity(f), 0) + 1

        story.append(
            Paragraph(
                f"This report consolidates <b>{total}</b> finding{'s' if total != 1 else ''} "
                "identified across the assessed scope, normalized from the scanning tools "
                "listed in the appendix. Findings are prioritized by severity below, with "
                "full technical detail provided for every Critical and High severity finding.",
                self.styles["Body"],
            )
        )
        story.append(Spacer(1, 14))

        rows = [[Paragraph("Severity", self.styles["TableHeader"]), Paragraph("Count", self.styles["TableHeader"])]]
        style_commands = [
            ("BACKGROUND", (0, 0), (-1, 0), DARK_BG),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ]
        for i, sev in enumerate(SEVERITY_ORDER, start=1):
            rows.append(
                [
                    Paragraph(
                        sev,
                        ParagraphStyle(
                            f"sev_label_{sev}",
                            parent=self.styles["Body"],
                            textColor=colors.white,
                            fontName="Helvetica-Bold",
                        ),
                    ),
                    Paragraph(str(counts[sev]), self.styles["Body"]),
                ]
            )
            style_commands.append(("BACKGROUND", (0, i), (0, i), SEVERITY_COLORS[sev]))

        table = Table(rows, colWidths=[2.5 * inch, 1.2 * inch])
        table.setStyle(TableStyle(style_commands))
        story.append(table)
        return story

    # --- Section: findings summary table, grouped by severity -------------------

    def _build_findings_table(self, findings: List[Any]) -> List[Any]:
        story: List[Any] = [Paragraph("Findings Summary", self.styles["SectionHeading"])]

        col_widths = [0.85 * inch, 2.2 * inch, 0.75 * inch, 1.05 * inch, 1.5 * inch, 0.95 * inch]
        headers = ["CVE", "Title", "Severity", "Tool", "Host / File", "Status"]

        grouped: Dict[str, List[Any]] = {sev: [] for sev in SEVERITY_ORDER}
        for f in findings:
            grouped[self._severity(f)].append(f)

        for sev in SEVERITY_ORDER:
            group = grouped[sev]
            if not group:
                continue

            group_label = Table([[Paragraph(f"{sev} ({len(group)})", self.styles["GroupHeader"])]], colWidths=[CONTENT_WIDTH])
            group_label.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), SEVERITY_COLORS[sev]),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ]
                )
            )

            rows = [[Paragraph(h, self.styles["TableHeader"]) for h in headers]]
            for f in group:
                rows.append(
                    [
                        Paragraph(self._escape(f.cve_id) or "—", self.styles["TableCell"]),
                        Paragraph(self._escape(f.title), self.styles["TableCell"]),
                        Paragraph(
                            sev,
                            ParagraphStyle(
                                f"cell_sev_{id(f)}",
                                parent=self.styles["TableCell"],
                                textColor=SEVERITY_COLORS[sev],
                                fontName="Helvetica-Bold",
                            ),
                        ),
                        Paragraph(self._escape(self._tool(f)), self.styles["TableCell"]),
                        Paragraph(self._escape(self._location_summary(f)), self.styles["TableCell"]),
                        Paragraph(self._escape(self._status(f)), self.styles["TableCell"]),
                    ]
                )

            table = Table(rows, colWidths=col_widths, repeatRows=1)
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), DARK_BG),
                        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ROW_ALT]),
                    ]
                )
            )

            story.append(group_label)
            story.append(Spacer(1, 2))
            story.append(table)
            story.append(Spacer(1, 14))

        return story

    # --- Section: detailed findings (Critical + High) ---------------------------

    def _build_detailed_findings(self, findings: List[Any]) -> List[Any]:
        detail_findings = [f for f in findings if self._severity(f) in DETAIL_SEVERITIES]
        detail_findings.sort(key=lambda f: SEVERITY_ORDER.index(self._severity(f)))

        story: List[Any] = [Paragraph("Detailed Findings (Critical &amp; High)", self.styles["SectionHeading"])]

        if not detail_findings:
            story.append(
                Paragraph(
                    "No Critical or High severity findings were identified in this assessment.",
                    self.styles["Body"],
                )
            )
            return story

        for i, f in enumerate(detail_findings):
            story.append(KeepTogether(self._build_finding_detail_block(f)))
            if i < len(detail_findings) - 1:
                story.append(Spacer(1, 10))
                story.append(self._divider())
                story.append(Spacer(1, 10))

        return story

    def _build_finding_detail_block(self, f: Any) -> List[Any]:
        sev = self._severity(f)
        color = SEVERITY_COLORS[sev]

        badge = Table(
            [[Paragraph(sev, ParagraphStyle(f"badge_{id(f)}", parent=self.styles["Body"], textColor=colors.white, fontName="Helvetica-Bold", fontSize=8))]],
            colWidths=[0.95 * inch],
        )
        badge.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), color),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ]
            )
        )

        title_row = Table(
            [[badge, Paragraph(self._escape(f.title), self.styles["FindingHeading"])]],
            colWidths=[1.05 * inch, CONTENT_WIDTH - 1.05 * inch],
        )
        title_row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))

        blocks: List[Any] = [title_row, Spacer(1, 6)]

        meta_bits = []
        if f.cve_id:
            meta_bits.append(f"CVE: {f.cve_id}")
        if f.cwe_id:
            meta_bits.append(f"CWE: {f.cwe_id}")
        if getattr(f, "owasp_category", None):
            meta_bits.append(f.owasp_category)
        meta_bits.append(f"Tool: {self._tool(f)}")
        meta_bits.append(f"Status: {self._status(f)}")
        blocks.append(Paragraph(" &nbsp;|&nbsp; ".join(self._escape(b) for b in meta_bits), self.styles["Meta"]))
        blocks.append(Spacer(1, 8))

        blocks.append(Paragraph("Description", self.styles["SubHeading"]))
        blocks.append(Paragraph(self._escape(f.description) or "No description provided.", self.styles["Body"]))

        blocks.append(Paragraph("CVSS Score", self.styles["SubHeading"]))
        blocks.append(Paragraph(self._cvss_summary(f), self.styles["Body"]))

        blocks.append(Paragraph("Location", self.styles["SubHeading"]))
        blocks.append(Paragraph(self._escape(self._location_detail(f)), self.styles["Body"]))

        blocks.append(Paragraph("Evidence / Proof of Concept", self.styles["SubHeading"]))
        if f.proof_of_concept:
            blocks.append(Paragraph(self._escape(f.proof_of_concept), self.styles["Mono"]))
        else:
            blocks.append(Paragraph("No proof-of-concept evidence recorded.", self.styles["Body"]))
        if getattr(f, "detection_method", None):
            blocks.append(Spacer(1, 3))
            blocks.append(Paragraph(f"<i>Detection method:</i> {self._escape(f.detection_method)}", self.styles["Body"]))

        blocks.append(Paragraph("Remediation Steps", self.styles["SubHeading"]))
        blocks.append(Paragraph(self._escape(f.recommended_fix) or "No remediation guidance recorded.", self.styles["Body"]))
        if getattr(f, "effort_level", None):
            blocks.append(Paragraph(f"<i>Estimated effort:</i> {self._escape(f.effort_level)}", self.styles["Body"]))
        if getattr(f, "mitigation", None):
            blocks.append(Paragraph(f"<i>Interim mitigation:</i> {self._escape(f.mitigation)}", self.styles["Body"]))

        refs = self._build_references(f)
        if refs:
            blocks.append(Paragraph("References", self.styles["SubHeading"]))
            for ref in refs:
                blocks.append(Paragraph(f"&bull; {self._escape(ref)}", self.styles["Body"]))

        return blocks

    def _divider(self) -> Table:
        line = Table([[""]], colWidths=[CONTENT_WIDTH], rowHeights=[1])
        line.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), BORDER)]))
        return line

    # --- Section: appendix --------------------------------------------------------

    def _build_appendix(self, findings: List[Any], scan_metadata: Dict[str, Any]) -> List[Any]:
        story: List[Any] = [Paragraph("Appendix", self.styles["SectionHeading"])]

        story.append(Paragraph("Affected Systems", self.styles["SubHeading"]))
        host_counts: Dict[str, int] = {}
        for f in findings:
            if f.host:
                host_counts[f.host] = host_counts.get(f.host, 0) + 1
        files = sorted({f.code_file for f in findings if getattr(f, "code_file", None)})

        if host_counts:
            rows = [[Paragraph("Host", self.styles["TableHeader"]), Paragraph("Findings", self.styles["TableHeader"])]]
            for host in sorted(host_counts):
                rows.append([Paragraph(host, self.styles["TableCell"]), Paragraph(str(host_counts[host]), self.styles["TableCell"])])
            table = Table(rows, colWidths=[3.5 * inch, 1.5 * inch])
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), DARK_BG),
                        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ROW_ALT]),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ]
                )
            )
            story.append(table)
            story.append(Spacer(1, 10))
        if files:
            story.append(Paragraph("<b>Affected code files:</b> " + self._escape(", ".join(files)), self.styles["Body"]))
            story.append(Spacer(1, 10))
        if not host_counts and not files:
            story.append(Paragraph("No affected systems recorded.", self.styles["Body"]))
            story.append(Spacer(1, 10))

        story.append(Paragraph("Scan Metadata", self.styles["SubHeading"]))
        scans = scan_metadata.get("scans") or []
        if scans:
            rows = [
                [Paragraph(h, self.styles["TableHeader"]) for h in ("Scan", "Scope", "Status", "Started", "Completed")]
            ]
            for s in scans:
                rows.append(
                    [
                        Paragraph(self._escape(s.get("name")) or "—", self.styles["TableCell"]),
                        Paragraph(self._escape(s.get("scope")) or "—", self.styles["TableCell"]),
                        Paragraph(self._escape(s.get("status")) or "—", self.styles["TableCell"]),
                        Paragraph(self._fmt_dt(s.get("started_at")), self.styles["TableCell"]),
                        Paragraph(self._fmt_dt(s.get("completed_at")), self.styles["TableCell"]),
                    ]
                )
            table = Table(rows, colWidths=[1.4 * inch, 2.1 * inch, 1.1 * inch, 1.35 * inch, 1.35 * inch])
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), DARK_BG),
                        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ROW_ALT]),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ]
                )
            )
            story.append(table)
        else:
            story.append(Paragraph("No scan metadata provided.", self.styles["Body"]))
        story.append(Spacer(1, 10))

        story.append(Paragraph("Tools Used", self.styles["SubHeading"]))
        tools = sorted({self._tool(f) for f in findings})
        story.append(Paragraph(self._escape(", ".join(tools)) if tools else "—", self.styles["Body"]))

        return story

    # --- Page furniture -----------------------------------------------------------

    @staticmethod
    def _draw_footer(canvas, doc) -> None:
        canvas.saveState()
        canvas.setStrokeColor(BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(0.6 * inch, 0.62 * inch, PAGE_WIDTH - 0.6 * inch, 0.62 * inch)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(TEXT_MUTED)
        canvas.drawString(0.6 * inch, 0.45 * inch, "VACE - Vulnerability Assessment Consolidation Engine - Confidential")
        canvas.drawRightString(PAGE_WIDTH - 0.6 * inch, 0.45 * inch, f"Page {doc.page}")
        canvas.restoreState()

    # --- Field helpers --------------------------------------------------------------

    @staticmethod
    def _severity(finding: Any) -> str:
        sev = getattr(finding, "severity_normalized", None)
        return getattr(sev, "value", sev) or "INFO"

    @staticmethod
    def _tool(finding: Any) -> str:
        tool = getattr(finding, "tool_source", None)
        return getattr(tool, "value", tool) or "—"

    @staticmethod
    def _status(finding: Any) -> str:
        status = getattr(finding, "remediation_status", None)
        value = getattr(status, "value", status) or "OPEN"
        return value.replace("_", " ").title()

    @staticmethod
    def _location_summary(finding: Any) -> str:
        if finding.host:
            return f"{finding.host}:{finding.port}" if finding.port else finding.host
        if getattr(finding, "code_file", None):
            return f"{finding.code_file}:{finding.code_line}" if finding.code_line else finding.code_file
        if getattr(finding, "url", None):
            return finding.url
        return "—"

    @staticmethod
    def _location_detail(finding: Any) -> str:
        if finding.host:
            bits = [f"Host: {finding.host}"]
            if finding.port:
                bits.append(f"Port: {finding.port}")
            if getattr(finding, "service", None):
                bits.append(f"Service: {finding.service}")
            return " | ".join(bits)
        if getattr(finding, "code_file", None):
            bits = [f"File: {finding.code_file}"]
            if getattr(finding, "code_line", None):
                bits.append(f"Line: {finding.code_line}")
            return " | ".join(bits)
        if getattr(finding, "url", None):
            bits = [f"URL: {finding.url}"]
            if getattr(finding, "parameter", None):
                bits.append(f"Parameter: {finding.parameter}")
            return " | ".join(bits)
        return "Location not recorded."

    @staticmethod
    def _cvss_band(score: float) -> str:
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        if score > 0:
            return "Low"
        return "None"

    def _cvss_summary(self, finding: Any) -> str:
        bits = []
        if getattr(finding, "cvss_v3", None) is not None:
            bits.append(f"CVSS v3: {finding.cvss_v3} ({self._cvss_band(finding.cvss_v3)})")
        if getattr(finding, "cvss_v4", None) is not None:
            bits.append(f"CVSS v4: {finding.cvss_v4}")
        if getattr(finding, "epss_score", None) is not None:
            bits.append(f"EPSS: {finding.epss_score:.0%}")
        return " &nbsp;|&nbsp; ".join(bits) if bits else "Not scored."

    @staticmethod
    def _build_references(finding: Any) -> List[str]:
        """Synthesizes reference links from CVE/CWE/OWASP identifiers.

        Findings don't carry a dedicated references field, so this builds the
        standard lookup URLs from whatever identifiers the finding does have.
        """
        refs = []
        if getattr(finding, "cve_id", None):
            refs.append(f"{finding.cve_id} - https://nvd.nist.gov/vuln/detail/{finding.cve_id}")
        if getattr(finding, "cwe_id", None):
            cwe_num = finding.cwe_id.replace("CWE-", "").strip()
            refs.append(f"{finding.cwe_id} - https://cwe.mitre.org/data/definitions/{cwe_num}.html")
        if getattr(finding, "owasp_category", None):
            refs.append(f"OWASP {finding.owasp_category}")
        return refs

    @staticmethod
    def _fmt_dt(value: Optional[Any]) -> str:
        if not value:
            return "—"
        if isinstance(value, str):
            return value
        return value.strftime("%B %d, %Y at %H:%M UTC")

    @staticmethod
    def _escape(text: Optional[Any]) -> str:
        if not text:
            return ""
        return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
