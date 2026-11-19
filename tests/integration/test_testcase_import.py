"""Custom test-case import (service + CLI) and creating a manual finding from a test case."""
from __future__ import annotations

import json

import pytest

from app.extensions import db
from app.findings import service as findings
from app.methodology import library
from app.models import ActivityLog, TestCase, Vulnerability
from app.services import engagements as engagement_service
from tests.conftest import engagement_data

BASE = "https://app.acme-corp.test"


def case(**overrides) -> dict:
    record = {
        "test_id": "CUSTOM-01", "category": "Authentication", "title": "SSO session fixation",
        "procedure": "Compare the session id before and after login.", "expected_results": "A new id is issued.",
        "default_severity": "high", "automation_level": "manual",
    }
    record.update(overrides)
    return record


@pytest.fixture
def seeded(app):
    library.seed_test_cases()
    return app


@pytest.fixture
def engagement(lead):
    item = engagement_service.create_engagement(
        engagement_data(primary_target_url=f"{BASE}/", authorized_scope=["app.acme-corp.test"], excluded_scope=[]), lead
    )
    engagement_service.confirm_authorization(item, lead, "SOW-TC", "CISO")
    engagement_service.transition(item, "active", lead)
    db.session.commit()
    library.seed_test_cases()
    return item


def get(test_id: str) -> TestCase:
    return db.session.scalar(db.select(TestCase).filter_by(test_id=test_id))


class TestImportService:
    def test_creates_custom_cases(self, seeded):
        summary = library.import_test_cases([case(), case(test_id="CUSTOM-02", title="Second")])
        assert (summary.created, summary.updated, summary.skipped) == (2, 0, 0)
        row = get("CUSTOM-01")
        assert row.framework == "Custom" and row.default_severity == "high" and row.title == "SSO session fixation"

    def test_reimport_updates_without_duplicating(self, seeded):
        library.import_test_cases([case()])
        summary = library.import_test_cases([case(title="Renamed")])
        assert summary.updated == 1 and summary.created == 0
        assert get("CUSTOM-01").title == "Renamed"
        assert db.session.scalar(db.select(db.func.count()).select_from(TestCase).filter_by(test_id="CUSTOM-01")) == 1

    def test_builtin_cases_are_never_overwritten(self, seeded):
        summary = library.import_test_cases([{"test_id": "WSTG-INFO-01", "category": "x", "title": "hijacked"}])
        assert summary.skipped == 1 and summary.changed == 0
        assert get("WSTG-INFO-01").framework == "OWASP WSTG" and get("WSTG-INFO-01").title != "hijacked"

    def test_framework_cannot_impersonate_a_builtin(self, seeded):
        summary = library.import_test_cases([case(framework="OWASP WSTG")])
        assert summary.skipped == 1 and summary.changed == 0

    @pytest.mark.parametrize(
        "record,fragment",
        [
            ({"category": "x", "title": "t"}, "test_id"),
            ({"test_id": "bad id!", "category": "x", "title": "t"}, "malformed"),
            ({"test_id": "C1", "title": "t"}, "category"),
            ({"test_id": "C1", "category": "x"}, "title"),
            ({"test_id": "C1", "category": "x", "title": "t", "default_severity": "fatal"}, "default_severity"),
            ({"test_id": "C1", "category": "x", "title": "t", "automation_level": "robot"}, "automation_level"),
            ({"test_id": "C1", "category": "x", "title": "t", "required_tools": "nmap"}, "required_tools"),
            ("not an object", "object"),
        ],
    )
    def test_invalid_records_are_skipped_with_a_reason(self, seeded, record, fragment):
        summary = library.import_test_cases([record])
        assert summary.changed == 0 and summary.skipped == 1
        assert any(fragment in error for error in summary.errors)

    def test_duplicate_test_id_in_one_file_is_rejected(self, seeded):
        summary = library.import_test_cases([case(), case()])
        assert summary.created == 1 and summary.skipped == 1 and any("duplicate" in e for e in summary.errors)

    def test_non_list_is_refused(self, seeded):
        with pytest.raises(library.MethodologyError, match="list of test cases"):
            library.import_test_cases({"test_id": "x"})

    def test_too_many_records_refused(self, seeded, monkeypatch):
        monkeypatch.setattr(library, "MAX_IMPORT", 2)
        with pytest.raises(library.MethodologyError, match="Too many"):
            library.import_test_cases([case(test_id=f"C{i}") for i in range(3)])

    def test_import_is_audited(self, seeded):
        library.import_test_cases([case()])
        assert db.session.scalar(db.select(ActivityLog).filter_by(action="methodology.cases_imported"))

    def test_custom_cases_do_not_affect_wstg_coverage(self, engagement):
        library.import_test_cases([case()])
        assert library.engagement_progress(engagement)["total"] == 97


class TestFileLoader:
    def test_plain_list(self, tmp_path):
        path = tmp_path / "t.json"
        path.write_text(json.dumps([case()]))
        assert library.load_testcase_file(path)[0]["test_id"] == "CUSTOM-01"

    def test_object_wrapper(self, tmp_path):
        path = tmp_path / "t.json"
        path.write_text(json.dumps({"test_cases": [case()]}))
        assert len(library.load_testcase_file(path)) == 1

    @pytest.mark.parametrize("content", ["{bad json", json.dumps({"nope": 1}), json.dumps("string")])
    def test_bad_files_are_refused(self, tmp_path, content):
        path = tmp_path / "t.json"
        path.write_text(content)
        with pytest.raises(library.MethodologyError):
            library.load_testcase_file(path)


class TestImportCli:
    def test_cli_imports_and_is_idempotent(self, app, tmp_path):
        library.seed_test_cases()
        path = tmp_path / "cases.json"
        path.write_text(json.dumps({"test_cases": [case(), case(test_id="CUSTOM-02", title="Two")]}))
        runner = app.test_cli_runner()
        result = runner.invoke(args=["ptp", "import-testcases", str(path)])
        assert result.exit_code == 0 and "2 created" in result.output
        assert get("CUSTOM-01") is not None
        again = runner.invoke(args=["ptp", "import-testcases", str(path)])
        assert "2 updated" in again.output

    def test_cli_reports_errors_and_exits_nonzero_when_nothing_imported(self, app, tmp_path):
        library.seed_test_cases()
        path = tmp_path / "bad.json"
        path.write_text(json.dumps([{"category": "x"}]))
        result = app.test_cli_runner().invoke(args=["ptp", "import-testcases", str(path)])
        assert result.exit_code == 1 and "test_id" in result.output

    def test_bundled_example_file_imports(self, app):
        from pathlib import Path

        import app as app_package

        library.seed_test_cases()
        example = Path(app_package.__file__).resolve().parent.parent / "docs" / "testcases.example.json"
        records = library.load_testcase_file(example)
        summary = library.import_test_cases(records)
        assert summary.created == len(records) and summary.skipped == 0


class TestFindingFromTestCase:
    def test_manual_finding_links_the_test_case(self, engagement, lead):
        wstg = get("WSTG-INPV-05")
        row = findings.create_manual_finding(engagement, lead, {"name": "SQLi", "url": f"{BASE}/x", "test_case_id": wstg.id})
        db.session.commit()
        assert row.test_case_id == wstg.id

    def test_bad_test_case_id_is_ignored(self, engagement, lead):
        row = findings.create_manual_finding(engagement, lead, {"name": "x", "url": f"{BASE}/x", "test_case_id": "999999"})
        db.session.commit()
        assert row.id is not None  # Classified normally; the bogus id did not break creation.

    def test_create_from_case_through_the_ui(self, client, login, engagement, lead):
        wstg = get("WSTG-ATHN-04")
        login("lead.tester")
        response = client.post(
            f"/methodology/library/{wstg.id}/finding",
            data={"engagement": engagement.id, "url": f"{BASE}/admin", "severity": "critical", "method": "GET"},
        )
        assert response.status_code == 302
        row = db.session.scalar(db.select(Vulnerability))
        assert row.test_case_id == wstg.id and row.name == wstg.title and row.severity == "critical"
        assert row.validation_status == "needs_manual_review"

    def test_out_of_scope_url_is_refused(self, client, login, engagement):
        wstg = get("WSTG-ATHN-04")
        login("lead.tester")
        client.post(f"/methodology/library/{wstg.id}/finding", data={"engagement": engagement.id, "url": "https://evil.test/"})
        assert db.session.scalar(db.select(Vulnerability)) is None

    def test_case_page_shows_the_form(self, client, login, engagement):
        wstg = get("WSTG-INPV-05")
        login("lead.tester")
        assert b"Create a finding from this test case" in client.get(f"/methodology/library/{wstg.id}").data

    def test_viewer_cannot_create_from_a_case(self, client, login, make_user, engagement):
        wstg = get("WSTG-INPV-05")
        viewer = make_user("viewer", "Auditor")
        engagement.testers.append(viewer)
        db.session.commit()
        login("viewer")
        body = client.get(f"/methodology/library/{wstg.id}").data
        assert b"Create a finding from this test case" not in body
        assert client.post(f"/methodology/library/{wstg.id}/finding", data={"engagement": engagement.id, "url": f"{BASE}/x"}).status_code == 403

    def test_unassigned_engagement_is_404(self, client, login, make_user, engagement):
        wstg = get("WSTG-INPV-05")
        make_user("tester2")
        login("tester2")
        assert client.post(f"/methodology/library/{wstg.id}/finding", data={"engagement": engagement.id, "url": f"{BASE}/x"}).status_code == 404

    def test_custom_category_case_page_renders(self, client, login, engagement):
        library.import_test_cases([case(test_id="CUSTOM-X", category="Supply Chain")])
        db.session.commit()
        login("lead.tester")
        row = get("CUSTOM-X")
        body = client.get(f"/methodology/library/{row.id}").data
        assert body and b"Supply Chain" in body
