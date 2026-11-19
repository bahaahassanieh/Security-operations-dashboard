"""Assessment orchestrator, automated methodology coverage, and expanded passive findings."""
from __future__ import annotations

import json

import pytest

from app.extensions import db
from app.manual import service as manual
from app.methodology import library
from app.models import (
    Asset,
    Endpoint,
    ExecutionJob,
    TestCase,
    TestExecution,
    Vulnerability,
    WebCookie,
)
from app.recon import parsers
from app.services import engagements as engagement_service
from app.services import jobs
from tests.conftest import engagement_data

BASE = "https://app.acme-corp.test"
ALL_METHODS = ["passive_recon", "active_recon", "port_scanning", "content_discovery"]


@pytest.fixture
def engagement(lead, app, tmp_path):
    app.config["JOB_DIR"] = tmp_path / "jobs"
    item = engagement_service.create_engagement(
        engagement_data(authorized_methods=ALL_METHODS, primary_target_url=f"{BASE}/",
                        authorized_scope=["app.acme-corp.test"], excluded_scope=[]),
        lead,
    )
    engagement_service.confirm_authorization(item, lead, "SOW-A", "CISO")
    engagement_service.transition(item, "active", lead)
    db.session.commit()
    library.seed_test_cases()
    return item


class TestHttpxHeaderParsing:
    def test_security_headers_are_extracted(self, tmp_path):
        line = json.dumps({
            "url": "https://a.test/", "status_code": 200,
            "header": {"strict_transport_security": "max-age=1", "x_frame_options": "DENY", "date": "now"},
        })
        path = tmp_path / "o"
        path.write_text(line)
        item = parsers.parse_httpx(path)[0]
        assert item["security_headers"] == {"strict_transport_security": "max-age=1", "x_frame_options": "DENY"}

    def test_missing_header_object_is_empty(self, tmp_path):
        path = tmp_path / "o"
        path.write_text(json.dumps({"url": "https://a.test/", "status_code": 200}))
        assert parsers.parse_httpx(path)[0]["security_headers"] == {}


class TestExpandedPassive:
    def _service(self, engagement, url, headers, status=200):
        db.session.add(Asset(engagement_id=engagement.id, asset_type="web_service", value=url, in_scope=True,
                             attributes={"status_code": status, "security_headers": headers}))

    def _types(self, engagement, actor):
        manual.run_passive_review(engagement, actor)
        db.session.commit()
        return {row.vulnerability_type for row in db.session.scalars(db.select(Vulnerability))}

    def test_missing_security_headers_are_flagged(self, engagement, lead):
        self._service(engagement, f"{BASE}/", {})
        db.session.commit()
        types = self._types(engagement, lead)
        assert {"hsts", "missing_security_headers", "clickjacking"} <= types

    def test_fully_hardened_service_has_no_header_findings(self, engagement, lead):
        self._service(engagement, f"{BASE}/", {
            "strict_transport_security": "max-age=31536000",
            "content_security_policy": "default-src 'self'; frame-ancestors 'none'",
            "x_frame_options": "DENY", "x_content_type_options": "nosniff",
        })
        db.session.commit()
        assert self._types(engagement, lead) == set()

    def test_error_responses_are_ignored(self, engagement, lead):
        self._service(engagement, f"{BASE}/", {}, status=500)
        db.session.commit()
        assert self._types(engagement, lead) == set()

    def test_directory_listing_is_flagged(self, engagement, lead):
        db.session.add(Endpoint(engagement_id=engagement.id, url=f"{BASE}/files/", path="/files/", status_code=200,
                                title="Index of /files", in_scope=True))
        db.session.commit()
        assert "directory_listing" in self._types(engagement, lead)

    def test_unauthenticated_admin_endpoint_is_flagged(self, engagement, lead):
        db.session.add(Endpoint(engagement_id=engagement.id, url=f"{BASE}/admin", path="/admin", status_code=200,
                                category="administration", requires_auth=False, in_scope=True))
        db.session.commit()
        self._types(engagement, lead)
        row = db.session.scalar(db.select(Vulnerability).filter_by(vulnerability_type="authentication_bypass"))
        assert row is not None and row.severity == "high"

    def test_candidates_stay_unverified(self, engagement, lead):
        self._service(engagement, f"{BASE}/", {})
        db.session.commit()
        self._types(engagement, lead)
        assert {row.validation_status for row in db.session.scalars(db.select(Vulnerability))} == {"detected"}


class TestAssessmentOrchestrator:
    def test_only_runnable_modules_are_planned(self, engagement, monkeypatch):
        monkeypatch.setattr(jobs, "resolve_tool", lambda name: "/bin/true" if name in {"dig", "httpx"} else None)
        runnable = [item["module"].name for item in jobs.assessment_plan(engagement) if item["blocked_reason"] is None]
        assert "dns" in runnable and "http_probe" in runnable and "passive_findings" in runnable
        assert "ports" not in runnable  # nmap not installed

    def test_passive_only_assessment_runs_and_records_coverage(self, lead, app, tmp_path, monkeypatch):
        # A passive-only engagement with no tools: only the no-traffic passive module runs.
        app.config["JOB_DIR"] = tmp_path / "jobs"
        monkeypatch.setattr(jobs, "resolve_tool", lambda name: None)
        engagement = engagement_service.create_engagement(
            engagement_data(authorized_methods=["passive_recon"], primary_target_url=f"{BASE}/",
                            authorized_scope=["app.acme-corp.test"], excluded_scope=[]),
            lead,
        )
        engagement_service.confirm_authorization(engagement, lead, "SOW-P", "CISO")
        engagement_service.transition(engagement, "active", lead)
        db.session.commit()
        library.seed_test_cases()
        db.session.add(Asset(engagement_id=engagement.id, asset_type="web_service", value=f"{BASE}/", in_scope=True,
                             attributes={"status_code": 200, "security_headers": {}}))
        db.session.commit()
        job = jobs.create_assessment_job(engagement, lead)
        db.session.commit()
        assert job.job_type == "full_assessment" and job.plan["modules"] == ["passive_findings"]
        jobs.execute_job(jobs.claim_next_job())
        db.session.refresh(job)
        assert job.status == "completed"
        assert db.session.scalar(db.select(Vulnerability)) is not None
        # Methodology coverage for the passive module's test cases was recorded.
        covered = {row.test_case.test_id: row for row in db.session.scalars(db.select(TestExecution))}
        assert "WSTG-CONF-07" in covered and covered["WSTG-CONF-07"].mode == "automated"
        assert covered["WSTG-CONF-07"].status == "in_progress"

    def test_no_runnable_modules_is_refused(self, lead, app, tmp_path):
        app.config["JOB_DIR"] = tmp_path / "jobs"
        item = engagement_service.create_engagement(
            engagement_data(authorized_methods=["manual_testing"], primary_target_url=f"{BASE}/",
                            authorized_scope=["app.acme-corp.test"], excluded_scope=[]),
            lead,
        )
        engagement_service.confirm_authorization(item, lead, "SOW", "CISO")
        engagement_service.transition(item, "active", lead)
        db.session.commit()
        with pytest.raises(jobs.JobError, match="No assessment modules"):
            jobs.create_assessment_job(item, lead)

    def test_one_active_job_per_engagement(self, engagement, lead):
        jobs.create_assessment_job(engagement, lead)
        db.session.commit()
        with pytest.raises(jobs.JobError, match="already running"):
            jobs.create_assessment_job(engagement, lead)


class TestCoverageRecording:
    def test_coverage_does_not_override_tester_results(self, engagement, lead):
        case = db.session.scalar(db.select(TestCase).filter_by(test_id="WSTG-CONF-07"))
        library.update_execution(engagement, case, lead, "passed", "Checked by hand.")
        db.session.commit()
        library.record_automated_coverage(engagement, ("WSTG-CONF-07", "WSTG-CONF-02"), lead)
        db.session.commit()
        kept = db.session.scalar(db.select(TestExecution).filter_by(test_case_id=case.id))
        assert kept.status == "passed" and kept.mode == "manual"
        other = db.session.scalar(db.select(TestExecution).join(TestCase).filter(TestCase.test_id == "WSTG-CONF-02"))
        assert other.status == "in_progress" and other.mode == "automated"

    def test_unknown_test_ids_are_ignored(self, engagement, lead):
        assert library.record_automated_coverage(engagement, ("WSTG-NOPE-99",), lead) == 0


class TestAssessPage:
    def test_assess_page_renders(self, client, login, engagement):
        login("lead.tester")
        body = client.get(f"/recon/engagements/{engagement.id}/assess").data
        assert b"Full assessment" in body and b"does not send attack payloads" in body

    def test_start_requires_confirmation(self, client, login, engagement):
        login("lead.tester")
        client.post(f"/recon/engagements/{engagement.id}/assess", data={})
        assert db.session.scalar(db.select(ExecutionJob)) is None

    def test_start_creates_a_job(self, client, login, engagement):
        login("lead.tester")
        response = client.post(f"/recon/engagements/{engagement.id}/assess", data={"confirm": "y"})
        assert response.status_code == 302
        job = db.session.scalar(db.select(ExecutionJob))
        assert job is not None and job.job_type == "full_assessment"

    def test_read_only_role_cannot_start(self, client, login, make_user, engagement):
        make_user("viewer", "Auditor")
        login("viewer")
        assert client.get(f"/recon/engagements/{engagement.id}/assess").status_code == 403

    def test_unassigned_user_gets_404(self, client, login, make_user, engagement):
        make_user("outsider")
        login("outsider")
        assert client.get(f"/recon/engagements/{engagement.id}/assess").status_code == 404


class TestAutoPassiveFindings:
    def _eng(self, lead, methods):
        item = engagement_service.create_engagement(
            engagement_data(authorized_methods=methods, primary_target_url=f"{BASE}/",
                            authorized_scope=["app.acme-corp.test"], excluded_scope=[]),
            lead,
        )
        engagement_service.confirm_authorization(item, lead, "SOW-AP", "CISO")
        engagement_service.transition(item, "active", lead)
        db.session.commit()
        return item

    def test_recon_job_appends_passive_findings(self, lead, app, tmp_path, monkeypatch):
        app.config["JOB_DIR"] = tmp_path / "jobs"
        monkeypatch.setattr(jobs, "resolve_tool", lambda name: "/bin/true")
        eng = self._eng(lead, ["active_recon", "passive_recon"])
        job = jobs.create_recon_job(eng, lead, ["http_probe"])
        db.session.commit()
        assert job.plan["modules"] == ["http_probe", "passive_findings"]

    def test_not_appended_without_passive_authorization(self, lead, app, tmp_path, monkeypatch):
        app.config["JOB_DIR"] = tmp_path / "jobs"
        monkeypatch.setattr(jobs, "resolve_tool", lambda name: "/bin/true")
        eng = self._eng(lead, ["active_recon"])
        job = jobs.create_recon_job(eng, lead, ["http_probe"])
        db.session.commit()
        assert job.plan["modules"] == ["http_probe"]

    def test_mapping_job_appends_passive_findings(self, lead, app, tmp_path):
        app.config["JOB_DIR"] = tmp_path / "jobs"
        eng = self._eng(lead, ["content_discovery", "passive_recon"])
        job = jobs.create_mapping_job(eng, lead, ["app_crawl"], {})
        db.session.commit()
        assert job.plan["modules"][-1] == "passive_findings" and job.plan["modules"].count("passive_findings") == 1

    def test_assessment_has_a_single_passive_step(self, engagement, lead):
        job = jobs.create_assessment_job(engagement, lead)
        db.session.commit()
        assert job.plan["modules"].count("passive_findings") == 1 and job.plan["modules"][-1] == "passive_findings"
