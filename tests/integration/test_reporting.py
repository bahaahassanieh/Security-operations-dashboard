"""CVSS calculator, evidence repository, remediation, retesting and report generation."""
from __future__ import annotations

import io
import json
import stat
import struct
import zlib
from pathlib import Path

import pytest

from app.extensions import db
from app.findings import service as findings
from app.findings.service import FindingError
from app.models import (
    ActivityLog,
    Evidence,
    Remediation,
    Report,
    Retest,
    ValidationStatus,
    Vulnerability,
)
from app.reporting import cvss
from app.reporting import evidence as evidence_service
from app.reporting import remediation as remediation_service
from app.reporting import service as report_service
from app.services import engagements as engagement_service
from tests.conftest import engagement_data

BASE = "https://app.acme-corp.test"


def png_bytes(width: int = 4, height: int = 4) -> bytes:
    """Build a minimal valid PNG without external libraries."""
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + b"\xff\x00\x00" * width for _ in range(height))
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


@pytest.fixture
def engagement(lead):
    item = engagement_service.create_engagement(
        engagement_data(primary_target_url=f"{BASE}/", authorized_scope=["app.acme-corp.test"], excluded_scope=[]), lead
    )
    engagement_service.confirm_authorization(item, lead, "SOW-6", "CISO")
    engagement_service.transition(item, "active", lead)
    db.session.commit()
    from app.methodology import library
    library.seed_test_cases()
    return item


@pytest.fixture
def finding(engagement, lead):
    row = findings.create_manual_finding(engagement, lead, {"name": "SQL injection", "url": f"{BASE}/search", "severity": "high", "parameter": "q"})
    db.session.commit()
    return row


def confirm(finding, lead):
    findings.add_evidence(finding, lead, "note", "Proof", "Reproduced manually.")
    findings.transition(finding, lead, "confirmed", "Reproduced in a clean environment.")
    db.session.commit()


class TestCvss:
    @pytest.mark.parametrize(
        "vector,score,severity",
        [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "medium"),
            ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8, "low"),
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.9, "medium"),
            ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9, "critical"),
            ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0, "none"),
            ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "high"),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"),
        ],
    )
    def test_official_known_answers(self, vector, score, severity):
        result = cvss.score_vector(vector)
        assert result.base_score == score and result.severity == severity

    def test_vector_round_trips(self):
        metrics = cvss.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert cvss.compute(metrics).vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    @pytest.mark.parametrize("vector", ["CVSS:3.0/AV:N", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:3.1/AV:N", "nonsense", "CVSS:3.1/AV:N/AV:N"])
    def test_invalid_vectors_are_rejected(self, vector):
        with pytest.raises(cvss.CvssError):
            cvss.score_vector(vector)

    @pytest.mark.parametrize("code", ["AV", "C", "S"])
    def test_missing_metric_is_rejected(self, code):
        metrics = cvss.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        del metrics[code]
        with pytest.raises(cvss.CvssError):
            cvss.compute(metrics)

    def test_setting_a_vector_on_a_finding_scores_it(self, finding, lead):
        findings.update_details(finding, lead, {"severity": "low", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
        db.session.commit()
        assert finding.cvss_score == 9.8 and finding.severity == "critical"

    def test_calculator_endpoint(self, client, login, make_user):
        make_user("calc.user")
        login("calc.user")
        assert client.get("/reports/cvss").status_code == 200
        response = client.post("/reports/cvss/score", json={"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"})
        assert response.get_json()["base_score"] == 9.8
        assert client.post("/reports/cvss/score", json={"AV": "X"}).status_code == 400


class TestEvidenceRepository:
    def test_screenshot_is_stored_on_disk_privately(self, finding, lead, app):
        item = evidence_service.add_file_evidence(finding, lead, "Alert popup", "shot.png", png_bytes())
        db.session.commit()
        assert item.evidence_type == "screenshot" and item.mime_type == "image/png"
        path = Path(item.storage_path)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600 and path.read_bytes() == png_bytes()
        assert item.content is None and item.origin == "tester"

    def test_non_image_posing_as_png_is_rejected(self, finding, lead):
        with pytest.raises(FindingError, match="not a readable image"):
            evidence_service.add_file_evidence(finding, lead, "Fake", "x.png", b"not really a png")

    def test_text_evidence_is_redacted_and_stored_inline(self, finding, lead):
        item = evidence_service.add_file_evidence(finding, lead, "Log", "capture.log", b"Cookie: sid=TOPSECRET\npassword=hunter2abc")
        db.session.commit()
        assert item.storage_path is None and "TOPSECRET" not in item.content and "hunter2abc" not in item.content

    @pytest.mark.parametrize("name,data,message", [("a.exe", b"x", "Upload a"), ("a.png", b"", "empty"), ("a.txt", "x".encode("utf-16"), "UTF-8")])
    def test_invalid_uploads_are_refused(self, finding, lead, name, data, message):
        with pytest.raises(FindingError, match=message):
            evidence_service.add_file_evidence(finding, lead, "t", name, data)

    def test_oversized_image_resolution_is_refused(self, finding, lead, monkeypatch):
        monkeypatch.setattr(evidence_service, "MAX_IMAGE_PIXELS", 4)
        with pytest.raises(FindingError, match="resolution"):
            evidence_service.add_file_evidence(finding, lead, "Big", "big.png", png_bytes(8, 8))

    def test_upload_and_download_through_the_ui(self, client, login, finding, lead):
        login("lead.tester")
        response = client.post(
            f"/evidence/findings/{finding.id}/upload",
            data={"title": "Screenshot", "file": (io.BytesIO(png_bytes()), "shot.png")}, content_type="multipart/form-data",
        )
        assert response.status_code == 302
        item = db.session.scalar(db.select(Evidence).filter_by(evidence_type="screenshot"))
        download = client.get(f"/evidence/{item.id}/file")
        assert download.status_code == 200 and "attachment" in download.headers["Content-Disposition"]
        assert download.data == png_bytes()

    def test_upload_is_audited(self, finding, lead):
        evidence_service.add_file_evidence(finding, lead, "Shot", "a.png", png_bytes())
        db.session.commit()
        assert db.session.scalar(db.select(ActivityLog).filter_by(action="evidence.uploaded"))

    def test_delete_removes_the_file(self, finding, lead):
        item = evidence_service.add_file_evidence(finding, lead, "Shot", "a.png", png_bytes())
        db.session.commit()
        path = Path(item.storage_path)
        evidence_service.delete_evidence(item, lead)
        db.session.commit()
        assert not path.exists() and db.session.scalar(db.select(Evidence)) is None

    def test_unassigned_user_cannot_reach_evidence(self, client, login, make_user, finding, lead):
        item = evidence_service.add_file_evidence(finding, lead, "Shot", "a.png", png_bytes())
        db.session.commit()
        make_user("outsider")
        login("outsider")
        assert client.get(f"/evidence/{item.id}/file").status_code == 404
        assert client.post(f"/evidence/findings/{finding.id}/upload", data={"title": "x", "file": (io.BytesIO(png_bytes()), "s.png")}, content_type="multipart/form-data").status_code == 404

    def test_viewer_cannot_upload_or_delete(self, client, login, make_user, finding, lead, engagement):
        item = evidence_service.add_file_evidence(finding, lead, "Shot", "a.png", png_bytes())
        db.session.commit()
        viewer = make_user("viewer", "Auditor")
        engagement.testers.append(viewer)
        db.session.commit()
        login("viewer")
        assert client.get(f"/evidence/{item.id}/file").status_code == 200
        assert client.post(f"/evidence/{item.id}/delete").status_code == 403


class TestRemediationAndRetest:
    def test_remediation_record_is_created(self, finding, lead):
        remediation_service.update_remediation(finding, lead, "in_progress", "App team", "2026-12-31", "Patch scheduled")
        db.session.commit()
        assert finding.remediation.status == "in_progress" and str(finding.remediation.due_date) == "2026-12-31"

    def test_resolved_sets_timestamp(self, finding, lead):
        remediation_service.update_remediation(finding, lead, "resolved", "", "", "")
        assert finding.remediation.resolved_at is not None

    def test_invalid_due_date_is_refused(self, finding, lead):
        with pytest.raises(FindingError, match="YYYY-MM-DD"):
            remediation_service.update_remediation(finding, lead, "open", "", "31/12/2026", "")

    def test_only_confirmed_findings_can_be_retested(self, finding, lead):
        with pytest.raises(FindingError, match="confirmed or remediated"):
            remediation_service.record_retest(finding, lead, "passed", "", None)

    def test_passed_retest_marks_remediated_and_verified(self, finding, lead):
        confirm(finding, lead)
        remediation_service.record_retest(finding, lead, "passed", "No longer reproduces.", None)
        db.session.commit()
        assert finding.validation_status == ValidationStatus.REMEDIATED and finding.retest_status == "passed"
        assert finding.remediation.status == "verified"

    def test_failed_retest_reopens_the_finding(self, finding, lead):
        confirm(finding, lead)
        remediation_service.update_remediation(finding, lead, "resolved", "", "", "")
        remediation_service.record_retest(finding, lead, "failed", "Still reproduces with the same request.", None)
        db.session.commit()
        assert finding.validation_status == ValidationStatus.RETEST_FAILED and finding.retest_status == "failed"
        assert finding.remediation.status == "open" and finding.remediation.resolved_at is None

    def test_failed_retest_needs_notes(self, finding, lead):
        confirm(finding, lead)
        with pytest.raises(FindingError, match="observed"):
            remediation_service.record_retest(finding, lead, "failed", "", None)

    def test_retest_records_a_status_change_and_audit(self, finding, lead):
        confirm(finding, lead)
        remediation_service.record_retest(finding, lead, "passed", "Fixed.", None)
        db.session.commit()
        assert db.session.scalar(db.select(ActivityLog).filter_by(action="retest.recorded"))
        assert finding.status_changes[-1].to_status == ValidationStatus.REMEDIATED

    def test_retest_evidence_must_belong_to_the_finding(self, finding, lead, engagement):
        confirm(finding, lead)
        other = findings.create_manual_finding(engagement, lead, {"name": "XSS", "url": f"{BASE}/x"})
        stray = findings.add_evidence(other, lead, "note", "x", "y")
        db.session.commit()
        with pytest.raises(FindingError, match="belongs to this finding"):
            remediation_service.record_retest(finding, lead, "passed", "", stray.id)

    def test_queue_lists_retestable_findings(self, finding, lead):
        confirm(finding, lead)
        assert finding in remediation_service.retest_queue(finding.engagement_id)

    def test_retest_through_the_ui(self, client, login, finding, lead):
        confirm(finding, lead)
        login("lead.tester")
        client.post(f"/retesting/findings/{finding.id}/remediation", data={"status": "resolved", "owner": "team"})
        client.post(f"/retesting/findings/{finding.id}/retest", data={"result": "passed", "notes": "Fixed"})
        db.session.refresh(finding)
        assert finding.validation_status == ValidationStatus.REMEDIATED


class TestReportGeneration:
    @pytest.fixture
    def with_findings(self, engagement, lead):
        confirmed = findings.create_manual_finding(engagement, lead, {"name": "SQL injection", "url": f"{BASE}/a", "severity": "critical"})
        findings.add_evidence(confirmed, lead, "http_capture", "PoC", "GET /a HTTP/1.1")
        findings.transition(confirmed, lead, "confirmed", "Reproduced manually in the lab.")
        db.session.add(Vulnerability(finding_uid="U-1", engagement_id=engagement.id, name="Unverified XSS", vulnerability_type="cross_site_scripting", severity="medium", dedup_fingerprint="u1", endpoint_url=f"{BASE}/b"))
        db.session.commit()
        return engagement

    @pytest.mark.parametrize("report_type", report_service.REPORT_TYPES)
    def test_every_report_type_generates_pdf_and_html(self, with_findings, lead, report_type):
        for fmt in ("pdf", "html"):
            report = report_service.generate(with_findings, lead, report_type, fmt, {"include_evidence": True, "include_unverified": True})
            db.session.commit()
            path = report_service.report_file_path(report)
            data = path.read_bytes()
            assert report.size_bytes == len(data) > 0
            assert (data[:4] == b"%PDF") if fmt == "pdf" else (b"<!doctype html>" in data[:60].lower())

    def test_report_file_is_private(self, with_findings, lead):
        report = report_service.generate(with_findings, lead, "technical", "pdf", {})
        db.session.commit()
        assert stat.S_IMODE(report_service.report_file_path(report).stat().st_mode) == 0o600

    def test_confirmed_and_unverified_are_separated(self, with_findings, lead):
        report = report_service.generate(with_findings, lead, "technical", "html", {"include_unverified": True})
        db.session.commit()
        html = report_service.report_file_path(report).read_bytes().decode()
        assert report.finding_count == 1  # Only the confirmed finding is counted.
        assert "SQL injection" in html and "Unverified XSS" in html
        assert "unverified detections" in html.lower() and "must not be treated as confirmed" in html

    def test_unverified_excluded_by_default(self, with_findings, lead):
        report = report_service.generate(with_findings, lead, "technical", "html", {})
        db.session.commit()
        html = report_service.report_file_path(report).read_bytes().decode()
        assert "Unverified XSS" not in html

    def test_hostile_finding_text_is_escaped_in_html(self, engagement, lead):
        payload = "<script>alert(1)</script>"
        row = findings.create_manual_finding(engagement, lead, {"name": payload, "url": f"{BASE}/x", "description": payload})
        findings.add_evidence(row, lead, "note", "x", "y")
        findings.transition(row, lead, "confirmed", "Reproduced by hand.")
        db.session.commit()
        report = report_service.generate(engagement, lead, "technical", "html", {})
        db.session.commit()
        html = report_service.report_file_path(report).read_bytes().decode()
        assert payload not in html and "&lt;script&gt;" in html

    def test_hostile_text_does_not_break_pdf(self, engagement, lead):
        row = findings.create_manual_finding(engagement, lead, {"name": "<b>x</b> & <i>y</i>", "url": f"{BASE}/x", "description": "a < b & c > d"})
        findings.add_evidence(row, lead, "note", "x", "y")
        findings.transition(row, lead, "confirmed", "Reproduced by hand.")
        db.session.commit()
        report = report_service.generate(engagement, lead, "technical", "pdf", {"include_evidence": True})
        db.session.commit()
        assert report_service.report_file_path(report).read_bytes()[:4] == b"%PDF"

    def test_screenshot_embeds_in_reports(self, engagement, lead):
        row = findings.create_manual_finding(engagement, lead, {"name": "Clickjacking", "url": f"{BASE}/x", "severity": "medium"})
        findings.add_evidence(row, lead, "note", "x", "y")
        findings.transition(row, lead, "confirmed", "Reproduced by hand.")
        evidence_service.add_file_evidence(row, lead, "Framed", "frame.png", png_bytes(8, 8))
        db.session.commit()
        for fmt in ("pdf", "html"):
            report = report_service.generate(engagement, lead, "technical", fmt, {"include_evidence": True})
            db.session.commit()
            data = report_service.report_file_path(report).read_bytes()
            if fmt == "html":
                assert b"data:image/png;base64," in data

    def test_generation_requires_authorization(self, lead):
        draft = engagement_service.create_engagement(engagement_data(name="Draft"), lead)
        db.session.commit()
        with pytest.raises(FindingError, match="authorization"):
            report_service.generate(draft, lead, "executive", "pdf", {})

    def test_generation_is_audited(self, with_findings, lead):
        report_service.generate(with_findings, lead, "executive", "pdf", {})
        db.session.commit()
        assert db.session.scalar(db.select(ActivityLog).filter_by(action="report.generated"))

    def test_generate_and_download_through_the_ui(self, client, login, with_findings):
        login("lead.tester")
        response = client.post("/reports/generate", data={"engagement": with_findings.id, "report_type": "executive", "format": "pdf"})
        assert response.status_code == 302
        report = db.session.scalar(db.select(Report))
        download = client.get(f"/reports/{report.id}/download")
        assert download.status_code == 200 and download.data[:4] == b"%PDF"
        assert "attachment" in download.headers["Content-Disposition"]

    def test_delete_report_through_the_ui(self, client, login, with_findings, lead):
        report = report_service.generate(with_findings, lead, "executive", "pdf", {})
        db.session.commit()
        path = report_service.report_file_path(report)
        login("lead.tester")
        client.post(f"/reports/{report.id}/delete")
        assert not path.exists() and db.session.scalar(db.select(Report)) is None

    def test_unassigned_user_cannot_download(self, client, login, make_user, with_findings, lead):
        report = report_service.generate(with_findings, lead, "executive", "pdf", {})
        db.session.commit()
        make_user("outsider")
        login("outsider")
        assert client.get(f"/reports/{report.id}/download").status_code == 404

    def test_read_only_role_cannot_generate(self, client, login, make_user, with_findings):
        viewer = make_user("viewer", "Client Viewer")
        with_findings.testers.append(viewer)
        db.session.commit()
        login("viewer")
        assert client.post("/reports/generate", data={"engagement": with_findings.id, "report_type": "executive", "format": "pdf"}).status_code == 403


class TestReportPages:
    def test_pages_render(self, client, login, finding, lead):
        confirm(finding, lead)
        login("lead.tester")
        for path in ("/evidence/", "/reports/", "/reports/cvss", "/retesting/",
                     f"/findings/{finding.id}"):
            assert client.get(path).status_code == 200, path
