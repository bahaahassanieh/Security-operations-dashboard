"""Render report data as self-contained HTML or as PDF (ReportLab)."""
from __future__ import annotations

import base64
import io
from xml.sax.saxutils import escape

from flask import render_template
from PIL import Image
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus import Image as RLImage

import logging

from app.findings.service import FindingError
from app.reporting.data import ReportData
from app.reporting.evidence import evidence_file_path

logger = logging.getLogger("ptp.reporting")

REPORT_TITLES = {
    "executive": "Executive Summary Report",
    "technical": "Technical Assessment Report",
    "reconnaissance": "Reconnaissance Report",
    "attack_surface": "Attack Surface Inventory",
    "api_security": "API Security Report",
    "retest": "Retest Report",
    "remediation": "Remediation Tracking Report",
}
# Which sections each report type contains, in order.
SECTIONS = {
    "executive": ("overview", "posture", "risk_summary", "top_findings", "recommendations", "methodology"),
    "technical": ("overview", "methodology", "risk_summary", "findings_detail", "remediation", "unverified"),
    "reconnaissance": ("overview", "recon"),
    "attack_surface": ("overview", "attack_surface"),
    "api_security": ("overview", "api", "api_findings"),
    "retest": ("overview", "retest"),
    "remediation": ("overview", "remediation"),
}
_SEVERITY_HEX = {"critical": "#c0392b", "high": "#d35400", "medium": "#b7950b", "low": "#1f78b4", "info": "#7f8c8d", "none": "#7f8c8d"}
_MAX_IMAGE_WIDTH = 150 * mm
_MAX_EVIDENCE_IMAGES = 60


def render_html(report_type: str, data: ReportData) -> str:
    """Render a standalone HTML document. Jinja autoescaping protects against hostile finding text."""
    return render_template(
        "reports/documents/report.html",
        report_type=report_type, title=REPORT_TITLES[report_type], sections=SECTIONS[report_type],
        data=data, severity_hex=_SEVERITY_HEX, images=_html_images(data),
    )


def _html_images(data: ReportData) -> dict[int, list[dict]]:
    """Base64-encode screenshot evidence for inline embedding, bounded in count."""
    result: dict[int, list[dict]] = {}
    if not data.options.get("include_evidence"):
        return result
    used = 0
    for finding_id, items in data.evidence_by_finding.items():
        for item in items:
            if item.evidence_type != "screenshot" or not item.storage_path or used >= _MAX_EVIDENCE_IMAGES:
                continue
            try:
                raw = evidence_file_path(item).read_bytes()
            except (FindingError, OSError) as exc:
                logger.debug("report image skipped: %s", exc)
                continue
            encoded = base64.b64encode(raw).decode("ascii")
            result.setdefault(finding_id, []).append({"title": item.title, "data_uri": f"data:{item.mime_type};base64,{encoded}"})
            used += 1
    return result


# --- PDF -------------------------------------------------------------------

def _styles() -> dict:
    base = getSampleStyleSheet()
    styles = {
        "title": ParagraphStyle("t", parent=base["Title"], fontSize=22, spaceAfter=6, textColor=colors.HexColor("#1b2540")),
        "h1": ParagraphStyle("h1", parent=base["Heading1"], fontSize=15, spaceBefore=14, spaceAfter=6, textColor=colors.HexColor("#1b2540")),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontSize=12, spaceBefore=10, spaceAfter=4, textColor=colors.HexColor("#2a3654")),
        "body": ParagraphStyle("b", parent=base["BodyText"], fontSize=9.5, leading=13, alignment=TA_LEFT),
        "small": ParagraphStyle("s", parent=base["BodyText"], fontSize=8, leading=11, textColor=colors.HexColor("#555")),
        "mono": ParagraphStyle("m", parent=base["Code"], fontSize=8, leading=11),
    }
    return styles


def _p(text, style) -> Paragraph:
    """Build a paragraph, escaping text and preserving line breaks."""
    safe = escape("" if text is None else str(text)).replace("\n", "<br/>")
    return Paragraph(safe, style)


def _severity_chip(level: str) -> Paragraph:
    colour = _SEVERITY_HEX.get(level, "#7f8c8d")
    return Paragraph(f'<font color="{colour}"><b>{escape(level.upper())}</b></font>', _styles()["body"])


def _key_value_table(rows: list[tuple[str, str]], styles) -> Table:
    data = [[_p(key, styles["small"]), _p(value, styles["body"])] for key, value in rows]
    table = Table(data, colWidths=[40 * mm, 120 * mm])
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#dddddd")),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return table


class _ReportBuilder:
    def __init__(self, report_type: str, data: ReportData):
        self.report_type = report_type
        self.data = data
        self.styles = _styles()
        self.flow: list = []

    def build(self) -> bytes:
        self._cover()
        for section in SECTIONS[self.report_type]:
            getattr(self, f"_section_{section}", self._noop)()
        buffer = io.BytesIO()
        document = SimpleDocTemplate(
            buffer, pagesize=A4, title=REPORT_TITLES[self.report_type],
            leftMargin=20 * mm, rightMargin=20 * mm, topMargin=18 * mm, bottomMargin=18 * mm,
        )
        document.build(self.flow, onFirstPage=self._footer, onLaterPages=self._footer)
        return buffer.getvalue()

    def _noop(self):
        pass

    def _footer(self, canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#888888"))
        canvas.drawString(20 * mm, 10 * mm, "CONFIDENTIAL — for the authorized recipient only")
        canvas.drawRightString(190 * mm, 10 * mm, f"Page {document.page}")
        canvas.restoreState()

    def _heading(self, text):
        self.flow.append(_p(text, self.styles["h1"]))

    def _cover(self):
        engagement = self.data.engagement
        self.flow += [
            Spacer(1, 40 * mm),
            _p(REPORT_TITLES[self.report_type], self.styles["title"]),
            _p(escape(engagement.name), self.styles["h2"]),
            Spacer(1, 6 * mm),
            _key_value_table([
                ("Client", engagement.client_name),
                ("Primary target", engagement.primary_target_url),
                ("Testing window", f"{engagement.start_date} to {engagement.end_date} (UTC)"),
                ("Report generated", self.data.generated_at),
                ("Authorization", engagement.authorization_reference or "Not recorded"),
            ], self.styles),
            Spacer(1, 10 * mm),
            _p("This report is confidential and intended only for the authorized recipient. It describes "
               "security testing performed under written client authorization.", self.styles["small"]),
            PageBreak(),
        ]

    def _section_overview(self):
        engagement = self.data.engagement
        self._heading("Engagement overview")
        self.flow.append(_key_value_table([
            ("Client", engagement.client_name),
            ("Status", engagement.status),
            ("Authorized by", engagement.authorization_signatory or "Not recorded"),
            ("Testing methods", ", ".join(engagement.authorized_methods or []) or "None recorded"),
            ("Validated findings", str(self.data.validated_count)),
            ("Unverified detections", str(len(self.data.unverified))),
        ], self.styles))
        if engagement.rules_of_engagement:
            self.flow += [_p("Rules of engagement", self.styles["h2"]), _p(engagement.rules_of_engagement, self.styles["body"])]

    def _section_posture(self):
        counts = self.data.severity_counts
        top = self.data.highest_severity
        statement = (
            f"Testing identified {self.data.validated_count} validated finding(s). "
            f"The highest-severity confirmed issue is rated {top.upper()}." if self.data.validated_count
            else "No findings were validated during this engagement."
        )
        self._heading("Overall security posture")
        self.flow.append(_p(statement, self.styles["body"]))
        self.flow.append(Spacer(1, 3 * mm))
        self.flow.append(_p(
            f"Critical: {counts['critical']}  |  High: {counts['high']}  |  Medium: {counts['medium']}  "
            f"|  Low: {counts['low']}  |  Info: {counts['info']}", self.styles["body"]))

    def _risk_table(self):
        counts = self.data.severity_counts
        header = ["Severity", "Critical", "High", "Medium", "Low", "Info"]
        row = ["Validated", counts["critical"], counts["high"], counts["medium"], counts["low"], counts["info"]]
        table = Table([header, [str(cell) for cell in row]], colWidths=[30 * mm] + [26 * mm] * 5)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1b2540")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 9), ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cccccc")),
            ("ALIGN", (1, 0), (-1, -1), "CENTER"), ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        return table

    def _section_risk_summary(self):
        self._heading("Risk distribution")
        self.flow.append(self._risk_table())

    def _section_top_findings(self):
        self._heading("Key findings")
        if not self.data.validated:
            self.flow.append(_p("No validated findings to report.", self.styles["body"]))
            return
        for finding in self.data.validated[:10]:
            self.flow.append(Table(
                [[_severity_chip(finding.severity), _p(f"<b>{escape(finding.name)}</b>", self.styles["body"])]],
                colWidths=[24 * mm, 136 * mm]))
            self.flow.append(_p(f"{finding.finding_uid} · {finding.endpoint_url or ''}", self.styles["small"]))
            self.flow.append(Spacer(1, 2 * mm))

    def _section_recommendations(self):
        self._heading("Prioritized recommendations")
        items = [f for f in self.data.validated if f.severity in ("critical", "high")] or self.data.validated
        if not items:
            self.flow.append(_p("No remediation actions are required from validated findings.", self.styles["body"]))
            return
        for index, finding in enumerate(items[:12], start=1):
            guidance = finding.remediation_guidance or "Review and remediate according to the detailed findings."
            self.flow.append(_p(f"<b>{index}. {escape(finding.name)}</b> ({finding.severity})", self.styles["body"]))
            self.flow.append(_p(guidance, self.styles["small"]))
            self.flow.append(Spacer(1, 2 * mm))

    def _section_methodology(self):
        progress = self.data.methodology
        self._heading("Testing methodology")
        self.flow.append(_p(
            "Testing followed the OWASP Web Security Testing Guide v4.2. "
            f"{progress['complete']} of {progress['total']} test cases were completed "
            f"({progress['percent']}% coverage).", self.styles["body"]))

    def _section_findings_detail(self):
        self._heading("Detailed findings")
        if not self.data.validated:
            self.flow.append(_p("No validated findings were recorded.", self.styles["body"]))
            return
        for finding in self.data.validated:
            self._finding_detail(finding)

    def _finding_detail(self, finding):
        styles = self.styles
        self.flow.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc"), spaceBefore=6, spaceAfter=4))
        self.flow.append(Table(
            [[_severity_chip(finding.severity), _p(f"<b>{escape(finding.name)}</b> ({finding.finding_uid})", styles["h2"])]],
            colWidths=[24 * mm, 136 * mm]))
        remediation = finding.remediation.status if finding.remediation else "open"
        self.flow.append(_key_value_table([
            ("Affected endpoint", f"{finding.http_method or ''} {finding.endpoint_url or 'Not recorded'}"),
            ("Parameter", finding.parameter or "—"),
            ("CWE", finding.cwe_id or "—"),
            ("OWASP", finding.owasp_category or "—"),
            ("CVSS", f"{finding.cvss_score} {finding.cvss_vector or ''}" if finding.cvss_score is not None else "Not scored"),
            ("Validation", finding.validation_status.replace("_", " ")),
            ("Remediation", remediation.replace("_", " ")),
            ("Detection source", finding.detection_source),
        ], styles))
        if finding.description:
            self.flow += [_p("Description", styles["h2"]), _p(finding.description, styles["body"])]
        tester_evidence = [e for e in self.data.evidence_by_finding.get(finding.id, []) if e.origin == "tester"]
        if tester_evidence:
            self.flow.append(_p("Evidence", styles["h2"]))
            for item in tester_evidence:
                self.flow.append(_p(f"• {escape(item.title)} ({item.evidence_type})", styles["small"]))
                if item.content:
                    self.flow.append(_p(item.content[:4000], styles["mono"]))
                self._embed_image(item)
        if finding.remediation_guidance:
            self.flow += [_p("Remediation", styles["h2"]), _p(finding.remediation_guidance, styles["body"])]

    def _embed_image(self, item):
        if item.evidence_type != "screenshot" or not item.storage_path:
            return
        try:
            raw = evidence_file_path(item).read_bytes()
            with Image.open(io.BytesIO(raw)) as probe:
                width, height = probe.size
            scale = min(1.0, _MAX_IMAGE_WIDTH / (width * (72.0 / 96.0)))
            draw_width = width * (72.0 / 96.0) * scale
            draw_height = height * (72.0 / 96.0) * scale
            self.flow.append(RLImage(io.BytesIO(raw), width=draw_width, height=draw_height))
            self.flow.append(Spacer(1, 2 * mm))
        except (FindingError, OSError, ValueError) as exc:
            logger.debug("report screenshot skipped: %s", exc)
            self.flow.append(_p("[screenshot could not be embedded]", self.styles["small"]))

    def _section_unverified(self):
        if not self.data.options.get("include_unverified") or not self.data.unverified:
            return
        self.flow.append(PageBreak())
        self._heading("Appendix: unverified detections")
        self.flow.append(_p(
            "The following items were reported by automated tools or passive review and have NOT been "
            "validated by a tester. They are provided for completeness and must not be treated as confirmed.",
            self.styles["small"]))
        table = [["Severity", "Finding", "Endpoint", "Source"]]
        for finding in self.data.unverified[:300]:
            table.append([finding.severity, finding.name[:60], (finding.endpoint_url or "")[:60], finding.detection_source])
        self._long_table(table, [22 * mm, 60 * mm, 60 * mm, 25 * mm])

    def _section_recon(self):
        self._heading("Reconnaissance summary")
        assets = self.data.assets
        self.flow.append(_key_value_table([
            ("Hostnames discovered", str(assets["subdomains"])),
            ("In-scope hostnames", str(assets["in_scope_subdomains"])),
            ("Web services", str(assets["services"])),
            ("Endpoints mapped", str(assets["endpoints"])),
        ], self.styles))
        if self.data.technologies:
            self.flow.append(_p("Technologies identified", self.styles["h2"]))
            table = [["Technology", "Version", "Source"]]
            for tech in self.data.technologies[:80]:
                table.append([tech.name, tech.version or "—", tech.source])
            self._long_table(table, [70 * mm, 45 * mm, 45 * mm])

    def _section_attack_surface(self):
        self._heading("Attack surface inventory")
        table = [["Method", "URL", "Status", "Category"]]
        for endpoint in self.data.endpoints_sample[:400]:
            table.append([endpoint.method, (endpoint.url or "")[:70], str(endpoint.status_code or "—"), endpoint.category or "—"])
        self._long_table(table, [18 * mm, 95 * mm, 20 * mm, 32 * mm])

    def _section_api(self):
        self._heading("API inventory")
        if not self.data.api_routes:
            self.flow.append(_p("No API routes were identified.", self.styles["body"]))
            return
        table = [["Method", "Route", "Requires sign-in"]]
        for endpoint in self.data.api_routes[:300]:
            auth = "Yes" if endpoint.requires_auth else ("Unknown" if endpoint.requires_auth is None else "No")
            table.append([endpoint.method, (endpoint.url or "")[:95], auth])
        self._long_table(table, [18 * mm, 120 * mm, 27 * mm])

    def _section_api_findings(self):
        api = [f for f in self.data.validated if (f.owasp_category or "").startswith("API") or "api" in f.vulnerability_type]
        if not api:
            return
        self._heading("API findings")
        for finding in api:
            self._finding_detail(finding)

    def _section_remediation(self):
        self._heading("Remediation tracking")
        if not self.data.remediation:
            self.flow.append(_p("No remediation records have been created.", self.styles["body"]))
            return
        table = [["Finding", "Owner", "Status", "Due", "Resolved"]]
        for record in self.data.remediation:
            finding = record.vulnerability
            table.append([
                finding.finding_uid if finding else "—", record.owner or "—", record.status.replace("_", " "),
                str(record.due_date or "—"), record.resolved_at.strftime("%Y-%m-%d") if record.resolved_at else "—",
            ])
        self._long_table(table, [30 * mm, 40 * mm, 30 * mm, 25 * mm, 25 * mm])

    def _section_retest(self):
        self._heading("Retest results")
        if not self.data.retests:
            self.flow.append(_p("No retests have been recorded.", self.styles["body"]))
            return
        table = [["Finding", "Result", "Performed", "Notes"]]
        for retest in self.data.retests:
            finding = retest.vulnerability
            table.append([
                finding.finding_uid if finding else "—", retest.result,
                retest.performed_at.strftime("%Y-%m-%d") if retest.performed_at else "—", (retest.notes or "")[:60],
            ])
        self._long_table(table, [30 * mm, 24 * mm, 26 * mm, 80 * mm])

    def _long_table(self, rows, col_widths):
        styles = self.styles
        data = [[_p(cell, styles["small"]) for cell in row] for row in rows]
        table = Table(data, colWidths=col_widths, repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1b2540")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#dddddd")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f6fb")]),
            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        self.flow.append(table)


def render_pdf(report_type: str, data: ReportData) -> bytes:
    """Render report data as a PDF document."""
    return _ReportBuilder(report_type, data).build()
