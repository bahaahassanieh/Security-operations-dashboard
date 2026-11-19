"""Scanner result import, correlation, validation workflow and the methodology library."""
from __future__ import annotations

import base64
import io
import json
import stat
from pathlib import Path

import pytest

from app import create_app
from app.extensions import db
from app.findings import parsers, service, taxonomy
from app.methodology import library, wstg
from app.models import (
    ActivityLog,
    Endpoint,
    Evidence,
    FindingImport,
    FindingSource,
    TestCase,
    TestExecution,
    Vulnerability,
)
from app.services import authz
from app.services import engagements as engagement_service
from tests.conftest import engagement_data

BASE = "https://app.acme-corp.test"


def nuclei_line(**overrides) -> str:
    record = {
        "template-id": "sqli-error", "host": BASE, "matched-at": f"{BASE}/search?q=1", "type": "http",
        "info": {"name": "SQL Injection", "severity": "critical", "description": "<b>Error based</b>",
                 "reference": ["https://example.test/ref"],
                 "classification": {"cwe-id": ["cwe-89"], "cvss-score": 9.8,
                                    "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
        "request": "GET /search?q=1 HTTP/1.1\r\nCookie: sid=SECRETCOOKIE\r\nAuthorization: Bearer abcdefghijklmnop",
        "response": "HTTP/1.1 500 Error\r\n\r\nsyntax error password=hunter2secret",
    }
    record.update(overrides)
    return json.dumps(record)


ZAP_REPORT = json.dumps({"site": [{"@name": BASE, "alerts": [
    {"alert": "SQL Injection", "riskcode": "3", "confidence": "2", "desc": "<p>Injectable</p>", "solution": "<p>Parameterize</p>",
     "cweid": "89", "reference": "<p>https://owasp.org/x</p>",
     "instances": [{"uri": f"{BASE}/search?q=abc", "method": "GET", "param": "q", "evidence": "SQL error"}]},
    {"alert": "Missing Anti-clickjacking Header", "riskcode": "2", "confidence": "2", "cweid": "1021",
     "instances": [{"uri": f"{BASE}/", "method": "GET"}]},
    {"alert": "Tool says false positive", "riskcode": "3", "confidence": "0", "instances": [{"uri": f"{BASE}/fp"}]},
]}]})


def burp_report() -> str:
    request = base64.b64encode(b"GET /profile?id=1 HTTP/1.1\r\nCookie: a=SECRETBURP\r\n\r\n").decode()
    return f"""<?xml version="1.0"?><!DOCTYPE issues [<!ELEMENT issues (issue*)>]>
<issues burpVersion="2026.1"><issue><name>Cross-site scripting (reflected)</name><host ip="1.1.1.1">{BASE}</host>
<path>/profile</path><location>/profile [id URL parameter]</location><severity>High</severity><confidence>Certain</confidence>
<issueBackground><![CDATA[<p>Background</p>]]></issueBackground><remediationBackground>Encode output</remediationBackground>
<vulnerabilityClassifications><![CDATA[<a>CWE-79: XSS</a>]]></vulnerabilityClassifications>
<requestresponse><request base64="true">{request}</request></requestresponse></issue>
<issue><name>Noise</name><host>{BASE}</host><path>/n</path><severity>False Positive</severity></issue></issues>"""


SQLMAP_CSV = f"Target URL,Place,Parameter,Technique(s),Note(s)\n{BASE}/item?id=1,GET,id,BEUST,\n"
GENERIC = json.dumps({"source": "Custom Engine", "findings": [
    {"name": "Exposed debug page", "severity": "medium", "url": f"{BASE}/debug", "cwe": "CWE-489", "evidence": "debug=true"}]})


@pytest.fixture
def engagement_ready(lead):
    item = engagement_service.create_engagement(engagement_data(primary_target_url=f"{BASE}/", authorized_scope=["app.acme-corp.test"], excluded_scope=[f"{BASE}/private"]), lead)
    engagement_service.confirm_authorization(item, lead, "SOW-4", "CISO")
    engagement_service.transition(item, "active", lead)
    db.session.commit()
    library.seed_test_cases()
    return item


def upload(engagement, actor, text, name="results.json", fmt="auto"):
    record = service.import_results(engagement, actor, name, text.encode(), fmt)
    db.session.commit()
    return record


def findings():
    return db.session.scalars(db.select(Vulnerability).order_by(Vulnerability.id)).all()


class TestParsers:
    @pytest.mark.parametrize(
        "text,expected",
        [(nuclei_line(), "nuclei"), (ZAP_REPORT, "zap"), (burp_report(), "burp"), (SQLMAP_CSV, "sqlmap"), (GENERIC, "generic")],
    )
    def test_formats_are_detected_from_content(self, text, expected):
        assert parsers.detect_format(text) == expected

    def test_nuclei(self):
        item = parsers.parse_report(nuclei_line()).findings[0]
        assert (item.severity, item.cwe, item.cvss_score, item.method) == ("critical", "CWE-89", 9.8, "GET")
        assert "<b>" not in item.description

    def test_zap_expands_instances_and_skips_tool_false_positives(self):
        report = parsers.parse_report(ZAP_REPORT)
        assert len(report.findings) == 2 and report.rejected == 1
        assert report.findings[0].parameter == "q" and report.findings[0].severity == "high"

    def test_burp_decodes_evidence_and_parameter(self):
        report = parsers.parse_report(burp_report())
        assert report.rejected == 1
        item = report.findings[0]
        assert (item.parameter, item.cwe, item.method) == ("id", "CWE-79", "GET") and "SECRETBURP" in item.evidence

    def test_sqlmap_csv(self):
        item = parsers.parse_report(SQLMAP_CSV).findings[0]
        assert (item.parameter, item.method, item.cwe, item.source) == ("id", "GET", "CWE-89", "sqlmap")

    def test_generic_source_is_sanitized(self):
        assert parsers.parse_report(GENERIC).findings[0].source == "custom_engine"

    def test_records_without_name_or_location_are_rejected(self):
        text = json.dumps([{"name": "No URL"}, {"url": f"{BASE}/x"}, "junk", {"name": "Good", "url": f"{BASE}/x"}])
        report = parsers.parse_report(text, "generic")
        assert len(report.findings) == 1 and report.rejected == 3

    @pytest.mark.parametrize("value,expected", [("HIGH", "high"), ("moderate", "medium"), ("bogus", "info"), (None, "info")])
    def test_severity_normalization(self, value, expected):
        assert parsers.severity(value) == expected

    @pytest.mark.parametrize("value", [11, -1, "abc", None])
    def test_invalid_cvss_scores_are_dropped(self, value):
        assert parsers.cvss_score(value) is None

    @pytest.mark.parametrize(
        "payload",
        ['<?xml version="1.0"?><!DOCTYPE issues [<!ENTITY e SYSTEM "file:///etc/passwd">]><issues><issue><name>&e;</name></issue></issues>',
         '<!DOCTYPE issues [<!ENTITY a "aa"><!ENTITY b "&a;&a;&a;">]><issues><issue><name>&b;</name></issue></issues>',
         "<issues><unclosed>"],
    )
    def test_hostile_xml_is_refused(self, payload):
        with pytest.raises(parsers.ReportError):
            parsers.parse_report(payload, "burp")

    @pytest.mark.parametrize("payload", ["[" * 200000, "{", "not a report", "<html></html>", "{}"])
    def test_malformed_files_are_refused(self, payload):
        with pytest.raises(parsers.ReportError):
            parsers.parse_report(payload)

    def test_record_limit(self):
        text = json.dumps([{"name": "x", "url": f"{BASE}/{i}"} for i in range(parsers.MAX_RECORDS + 1)])
        with pytest.raises(parsers.ReportError, match="more than"):
            parsers.parse_report(text, "generic")


class TestTaxonomy:
    @pytest.mark.parametrize(
        "name,key",
        [("SQL Injection", "sql_injection"), ("SQLi error based", "sql_injection"), ("Cross-site scripting (reflected)", "cross_site_scripting"),
         ("DOM based XSS", "dom_xss"), ("Stored XSS", "stored_xss"), ("Missing Anti-clickjacking Header", "clickjacking"),
         ("Server-Side Request Forgery", "ssrf"), ("Path Traversal", "path_traversal")],
    )
    def test_names_map_to_one_class(self, name, key):
        assert taxonomy.classify(name)[0] == key

    def test_cwe_is_used_when_the_name_is_unknown(self):
        assert taxonomy.classify("Vendor rule 1234", "CWE-89")[0] == "sql_injection"

    def test_every_class_references_a_real_test_case(self):
        ids = {case.test_id for case in wstg.CASES}
        assert all(item.wstg in ids for item in taxonomy.CLASSES if item.wstg)


class TestImport:
    def test_every_imported_finding_starts_unverified(self, engagement_ready, lead):
        upload(engagement_ready, lead, nuclei_line())
        upload(engagement_ready, lead, burp_report(), "burp.xml")
        assert {row.validation_status for row in findings()} == {"detected"}

    def test_file_claiming_confirmation_is_still_unverified(self, engagement_ready, lead):
        text = json.dumps([{"name": "XSS", "url": f"{BASE}/a", "validation_status": "confirmed", "confirmed": True, "confidence": "Certain"}])
        upload(engagement_ready, lead, text)
        assert findings()[0].validation_status == "detected"

    def test_fields_are_normalized_and_mapped(self, engagement_ready, lead):
        upload(engagement_ready, lead, nuclei_line())
        row = findings()[0]
        assert (row.vulnerability_type, row.cwe_id, row.test_case.test_id) == ("sql_injection", "CWE-89", "WSTG-INPV-05")
        assert row.owasp_category.startswith("A03") and row.cvss_score == 9.8

    def test_out_of_scope_results_are_counted_and_never_stored(self, engagement_ready, lead):
        text = json.dumps([
            {"name": "XSS", "url": "https://evil.example.net/a"}, {"name": "XSS", "url": f"{BASE}/private/x"},
            {"name": "XSS", "url": "http://169.254.169.254/latest"}, {"name": "XSS", "url": f"{BASE}/ok"}])
        record = upload(engagement_ready, lead, text)
        assert record.out_of_scope_count == 3 and record.created_count == 1
        assert [row.endpoint_url for row in findings()] == [f"{BASE}/ok"]

    def test_secrets_are_redacted_from_evidence_and_urls(self, engagement_ready, lead):
        upload(engagement_ready, lead, nuclei_line(**{"matched-at": f"{BASE}/x?token=URLSECRET1"}))
        row = findings()[0]
        content = row.evidence_items[0].content
        for secret in ("SECRETCOOKIE", "abcdefghijklmnop", "hunter2secret"):
            assert secret not in content
        assert "URLSECRET1" not in row.endpoint_url

    def test_same_weakness_from_two_tools_is_correlated(self, engagement_ready, lead):
        upload(engagement_ready, lead, json.dumps([{"name": "SQL Injection", "url": f"{BASE}/search?q=1", "parameter": "q", "source": "engine_a", "severity": "medium"}]))
        record = upload(engagement_ready, lead, ZAP_REPORT, "zap.json")
        rows = [row for row in findings() if row.vulnerability_type == "sql_injection"]
        assert len(rows) == 1 and record.merged_count == 1
        assert {item.source for item in rows[0].sources} == {"engine_a", "zap"} and rows[0].severity == "high"

    def test_different_parameter_or_endpoint_is_a_separate_finding(self, engagement_ready, lead):
        items = [{"name": "XSS", "url": f"{BASE}/a", "parameter": "x"}, {"name": "XSS", "url": f"{BASE}/a", "parameter": "y"},
                 {"name": "XSS", "url": f"{BASE}/b", "parameter": "x"}]
        assert upload(engagement_ready, lead, json.dumps(items)).created_count == 3

    def test_exact_repeat_inside_a_file_counts_as_duplicate(self, engagement_ready, lead):
        item = {"name": "XSS", "url": f"{BASE}/a", "evidence": "same"}
        record = upload(engagement_ready, lead, json.dumps([item, item]))
        assert record.created_count == 1 and record.duplicate_count == 1
        assert db.session.scalar(db.select(db.func.count()).select_from(FindingSource)) == 1

    def test_identical_file_is_refused(self, engagement_ready, lead):
        upload(engagement_ready, lead, GENERIC)
        with pytest.raises(service.FindingError, match="already imported"):
            upload(engagement_ready, lead, GENERIC, "renamed.json")

    def test_tester_decisions_survive_reimport(self, engagement_ready, lead):
        upload(engagement_ready, lead, json.dumps([{"name": "XSS", "url": f"{BASE}/a", "severity": "low", "evidence": "one"}]))
        row = findings()[0]
        service.transition(row, lead, "false_positive", "Encoded correctly in every context.")
        db.session.commit()
        upload(engagement_ready, lead, json.dumps([{"name": "XSS", "url": f"{BASE}/a", "severity": "critical", "evidence": "two"}]))
        db.session.refresh(row)
        assert row.validation_status == "false_positive" and row.severity == "low"

    def test_redetected_remediated_finding_returns_to_review(self, engagement_ready, lead):
        upload(engagement_ready, lead, json.dumps([{"name": "XSS", "url": f"{BASE}/a", "evidence": "one"}]))
        row = findings()[0]
        service.add_evidence(row, lead, "note", "Proof", "Reproduced manually.")
        service.transition(row, lead, "confirmed", "Reproduced in a clean browser.")
        service.transition(row, lead, "remediated", "")
        db.session.commit()
        upload(engagement_ready, lead, json.dumps([{"name": "XSS", "url": f"{BASE}/a", "evidence": "two"}]))
        db.session.refresh(row)
        assert row.validation_status == "needs_manual_review"

    def test_finding_links_to_mapped_endpoint(self, engagement_ready, lead):
        endpoint = Endpoint(engagement_id=engagement_ready.id, url=f"{BASE}/search", path="/search", method="GET", in_scope=True)
        db.session.add(endpoint)
        db.session.commit()
        upload(engagement_ready, lead, nuclei_line())
        assert findings()[0].endpoint_id == endpoint.id

    def test_stored_file_is_private_and_import_is_audited(self, engagement_ready, lead):
        record = upload(engagement_ready, lead, GENERIC)
        assert stat.S_IMODE(Path(record.storage_path).stat().st_mode) == 0o600
        assert db.session.scalar(db.select(ActivityLog).filter_by(action="findings.imported")) is not None

    def test_draft_engagement_is_refused(self, lead):
        item = engagement_service.create_engagement(engagement_data(), lead)
        with pytest.raises(service.FindingError, match="authorization"):
            service.import_results(item, lead, "a.json", GENERIC.encode())

    @pytest.mark.parametrize(
        "name,data,message",
        [("a.exe", b"[]", "Upload a"), ("../../etc/passwd", b"[]", "Upload a"), ("a.json", b"   ", "empty"),
         ("a.json", b"abc\x00def", "not a text"), ("a.json", b"\xff\xfe\x80", "UTF-8")],
    )
    def test_invalid_uploads_are_refused(self, engagement_ready, lead, name, data, message):
        with pytest.raises(service.FindingError, match=message):
            service.import_results(engagement_ready, lead, name, data)

    def test_failed_import_leaves_nothing_behind(self, engagement_ready, lead, app):
        with pytest.raises(service.FindingError):
            service.import_results(engagement_ready, lead, "a.json", b"{broken")
        db.session.rollback()
        assert db.session.scalar(db.select(db.func.count()).select_from(FindingImport)) == 0
        assert not list(Path(app.config["IMPORT_DIR"]).rglob("*.upload"))


class TestValidationWorkflow:
    @pytest.fixture
    def finding(self, engagement_ready, lead):
        upload(engagement_ready, lead, nuclei_line())
        return findings()[0]

    def test_scanner_output_alone_cannot_confirm(self, finding, lead):
        assert finding.evidence_items and finding.evidence_items[0].origin == "import"
        with pytest.raises(service.FindingError, match="your own validation evidence"):
            service.transition(finding, lead, "confirmed", "The scanner says it is real.")
        assert finding.validation_status == "detected"
        assert db.session.scalar(db.select(ActivityLog).filter_by(action="finding.validation_denied", outcome="denied"))

    def test_confirmation_needs_justification(self, finding, lead):
        service.add_evidence(finding, lead, "http_capture", "Proof", "GET / HTTP/1.1")
        with pytest.raises(service.FindingError, match="at least"):
            service.transition(finding, lead, "confirmed", "yes")

    def test_confirmation_records_who_and_when(self, finding, lead):
        service.add_evidence(finding, lead, "http_capture", "Proof", "GET / HTTP/1.1")
        service.transition(finding, lead, "confirmed", "Reproduced manually with a benign value.")
        db.session.commit()
        assert finding.validated_by_id == lead.id and finding.validated_at is not None
        assert finding.status_changes[-1].from_status == "detected"

    def test_false_positive_needs_justification(self, finding, lead):
        with pytest.raises(service.FindingError):
            service.transition(finding, lead, "false_positive", "")

    @pytest.mark.parametrize("target", ["remediated", "retest_failed", "accepted_risk", "bogus"])
    def test_invalid_transitions_are_refused(self, finding, lead, target):
        with pytest.raises(service.FindingError, match="cannot move"):
            service.transition(finding, lead, target, "A long enough justification.")

    def test_remediation_sets_retest_pending(self, finding, lead):
        service.add_evidence(finding, lead, "note", "Proof", "Reproduced.")
        service.transition(finding, lead, "confirmed", "Reproduced in a clean browser.")
        service.transition(finding, lead, "remediated", "")
        assert finding.retest_status == "pending"
        service.transition(finding, lead, "retest_failed", "The issue still reproduces.")
        assert finding.retest_status == "failed"

    def test_tester_evidence_is_redacted(self, finding, lead):
        item = service.add_evidence(finding, lead, "http_capture", "Proof", "Cookie: sid=TOPSECRET\npassword=abc12345")
        assert "TOPSECRET" not in item.content and "abc12345" not in item.content

    def test_every_status_can_be_reached(self):
        reachable = {status for targets in service.TRANSITIONS.values() for status in targets}
        assert reachable | {"detected"} == set(service.TRANSITIONS)

    def test_manual_finding_needs_review_and_must_be_in_scope(self, engagement_ready, lead):
        row = service.create_manual_finding(engagement_ready, lead, {"name": "IDOR", "url": f"{BASE}/invoice", "severity": "high"})
        assert row.validation_status == "needs_manual_review" and row.detection_source == "manual"
        db.session.flush()
        db.session.refresh(row)
        assert [item.justification for item in row.status_changes] == ["Entered manually by a tester."]
        with pytest.raises(service.FindingError, match="outside"):
            service.create_manual_finding(engagement_ready, lead, {"name": "IDOR", "url": "https://evil.example.net/"})
        with pytest.raises(service.FindingError, match="existing finding"):
            service.create_manual_finding(engagement_ready, lead, {"name": "IDOR", "url": f"{BASE}/invoice"})


class TestUploadPanel:
    def post(self, client, engagement, text=GENERIC, name="results.json", **extra):
        data = {"report": (io.BytesIO(text.encode() if isinstance(text, str) else text), name), "confirm": "y", "format": "auto"}
        data.update(extra)
        return client.post(f"/findings/imports?engagement={engagement.id}", data=data, content_type="multipart/form-data")

    def test_upload_through_the_panel(self, client, login, engagement_ready):
        login("lead.tester")
        assert self.post(client, engagement_ready).status_code == 302
        assert len(findings()) == 1
        body = client.get(f"/findings/imports?engagement={engagement_ready.id}").data
        assert b"results.json" in body and b"does not launch scans" in body

    def test_authorization_confirmation_is_required(self, client, login, engagement_ready):
        login("lead.tester")
        self.post(client, engagement_ready, confirm="")
        assert findings() == []

    def test_oversized_upload_is_refused(self, client, login, engagement_ready, app):
        app.config["IMPORT_MAX_BYTES"] = 1024
        login("lead.tester")
        response = self.post(client, engagement_ready, text="x" * (200 * 1024))
        assert response.status_code in (302, 413) and findings() == []

    def test_upload_limit_does_not_apply_to_other_routes(self, client, login, engagement_ready, app):
        login("lead.tester")
        response = client.post("/account/password", data={"current_password": "x" * (3 * 1024 * 1024)})
        assert response.status_code == 413

    def test_viewer_cannot_upload(self, client, login, make_user, engagement_ready):
        viewer = make_user("view.only", "Auditor")
        engagement_ready.testers.append(viewer)
        db.session.commit()
        login("view.only")
        assert self.post(client, engagement_ready).status_code == 403

    def test_unassigned_user_gets_404(self, client, login, make_user, engagement_ready, lead):
        upload(engagement_ready, lead, GENERIC)
        row = findings()[0]
        make_user("outsider")
        login("outsider")
        for path in (f"/findings/?engagement={engagement_ready.id}", f"/findings/{row.id}",
                     f"/findings/imports?engagement={engagement_ready.id}", f"/methodology/?engagement={engagement_ready.id}"):
            assert client.get(path).status_code == 404, path
        assert client.post(f"/findings/{row.id}/validate", data={"status": "false_positive"}).status_code == 404
        assert self.post(client, engagement_ready).status_code == 404

    def test_role_without_validate_permission_cannot_validate(self, client, login, make_user, engagement_ready, lead):
        upload(engagement_ready, lead, GENERIC)
        row = findings()[0]
        viewer = make_user("client.user", "Client Viewer")
        engagement_ready.testers.append(viewer)
        db.session.commit()
        login("client.user")
        assert client.get(f"/findings/{row.id}").status_code == 200
        assert client.post(f"/findings/{row.id}/validate", data={"status": "false_positive", "justification": "long enough text"}).status_code == 403

    def test_hostile_report_content_is_escaped(self, client, login, engagement_ready, lead):
        payload = "<script>alert(1)</script>"
        text = json.dumps([{"name": payload, "url": f"{BASE}/a", "description": "x", "evidence": payload, "parameter": payload, "source": payload}])
        upload(engagement_ready, lead, text)
        row = findings()[0]
        login("lead.tester")
        for path in (f"/findings/?engagement={engagement_ready.id}", f"/findings/{row.id}"):
            body = client.get(path).data
            assert payload.encode() not in body and b"&lt;script&gt;" in body

    def test_csrf_is_required_for_uploads(self, tmp_path):
        application = create_app("testing", {"SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'c.db'}", "WTF_CSRF_ENABLED": True})
        with application.app_context():
            db.create_all()
            authz.seed_rbac()
            response = application.test_client().post("/findings/imports", data={"report": (io.BytesIO(b"[]"), "a.json")}, content_type="multipart/form-data")
            assert response.status_code == 400
            db.session.remove()
            db.engine.dispose()

    def test_pages_render(self, client, login, engagement_ready, lead):
        upload(engagement_ready, lead, nuclei_line())
        row = findings()[0]
        login("lead.tester")
        for path in ("/findings/", f"/findings/?engagement={engagement_ready.id}&status=awaiting&severity=critical&q=sql",
                     f"/findings/{row.id}", "/findings/new", "/findings/imports", "/findings/imports/template.json",
                     "/methodology/", f"/methodology/?engagement={engagement_ready.id}&category=INPV", "/methodology/library",
                     "/methodology/library?category=ATHN&q=lock"):
            assert client.get(path).status_code == 200, path

    def test_generic_template_can_be_imported(self, client, login, engagement_ready):
        login("lead.tester")
        template = client.get("/findings/imports/template.json").data.decode().replace("app.example.com", "app.acme-corp.test")
        assert self.post(client, engagement_ready, text=template).status_code == 302
        assert findings()[0].vulnerability_type == "cross_site_scripting"

    def test_full_validation_through_the_ui(self, client, login, engagement_ready, lead):
        upload(engagement_ready, lead, GENERIC)
        row = findings()[0]
        login("lead.tester")
        client.post(f"/findings/{row.id}/validate", data={"status": "confirmed", "justification": "Reproduced by hand today."})
        db.session.refresh(row)
        assert row.validation_status == "detected"
        client.post(f"/findings/{row.id}/evidence", data={"evidence_type": "note", "title": "Proof", "content": "Reproduced."})
        client.post(f"/findings/{row.id}/validate", data={"status": "confirmed", "justification": "Reproduced by hand today."})
        db.session.refresh(row)
        assert row.validation_status == "confirmed"


class TestMethodology:
    def test_library_is_complete_for_wstg_42(self):
        counts = {code: 0 for code in wstg.CATEGORIES}
        for case in wstg.CASES:
            counts[case.category] += 1
        assert counts == {"INFO": 10, "CONF": 11, "IDNT": 5, "ATHN": 10, "ATHZ": 4, "SESS": 9, "INPV": 19, "ERRH": 2,
                          "CRYP": 4, "BUSL": 9, "CLNT": 13, "APIT": 1}
        assert len({case.code for case in wstg.CASES}) == 97

    def test_every_case_has_every_required_field(self, app):
        library.seed_test_cases()
        rows = db.session.scalars(db.select(TestCase)).all()
        assert len(rows) == 107
        for row in rows:
            for field in ("test_id", "framework", "framework_version", "framework_reference", "description", "procedure",
                          "required_tools", "expected_results", "evidence_requirements", "default_severity",
                          "validation_criteria", "remediation_guidance"):
                assert getattr(row, field), (row.test_id, field)

    def test_seeding_is_repeatable_and_keeps_results(self, engagement_ready, lead):
        case = db.session.scalar(db.select(TestCase).filter_by(test_id="WSTG-INFO-01"))
        library.update_execution(engagement_ready, case, lead, "passed", "Reviewed.")
        db.session.commit()
        library.seed_test_cases()
        assert db.session.scalar(db.select(db.func.count()).select_from(TestCase)) == 107
        assert db.session.scalar(db.select(TestExecution)).status == "passed"

    def test_progress_is_calculated(self, engagement_ready, lead):
        cases = db.session.scalars(db.select(TestCase).filter_by(category="ERRH").order_by(TestCase.test_id)).all()
        library.update_execution(engagement_ready, cases[0], lead, "passed", "")
        library.update_execution(engagement_ready, cases[1], lead, "failed", "Stack trace shown.")
        db.session.commit()
        summary = library.engagement_progress(engagement_ready)
        entry = next(item for item in summary["categories"] if item["code"] == "ERRH")
        assert (entry["complete"], entry["failed"], entry["percent"]) == (2, 1, 100)
        assert summary["complete"] == 2 and summary["total"] == 97

    def test_invalid_status_is_refused(self, engagement_ready, lead):
        case = db.session.scalar(db.select(TestCase))
        with pytest.raises(library.MethodologyError):
            library.update_execution(engagement_ready, case, lead, "hacked", "")

    def test_status_update_through_the_ui(self, client, login, engagement_ready):
        case = db.session.scalar(db.select(TestCase).filter_by(test_id="WSTG-SESS-02"))
        login("lead.tester")
        response = client.post(f"/methodology/engagements/{engagement_ready.id}/cases/{case.id}", data={"status": "in_progress", "notes": "Started"})
        assert response.status_code == 302
        assert db.session.scalar(db.select(TestExecution)).status == "in_progress"

    def test_evidence_table_records_origin(self, engagement_ready, lead):
        upload(engagement_ready, lead, nuclei_line())
        assert db.session.scalar(db.select(Evidence)).origin == "import"
