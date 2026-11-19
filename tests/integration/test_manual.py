"""Manual testing workspace: workflows, authorization matrix, analyzers, passive review and API review."""
from __future__ import annotations

import ast
import base64
import json
from pathlib import Path

import pytest

import app as app_package
from app.extensions import db
from app.findings.service import FindingError
from app.findings import service as findings
from app.manual import analyzers, service
from app.manual.playbooks import PLAYBOOKS
from app.methodology import api_top10, library, wstg
from app.models import (
    ActivityLog,
    Asset,
    AuthzCheck,
    Endpoint,
    EndpointParameter,
    Evidence,
    ManualWorkflow,
    TestCase,
    TestExecution,
    Vulnerability,
    WebCookie,
    WebForm,
    WorkflowStep,
)
from app.services import engagements as engagement_service
from tests.conftest import engagement_data

BASE = "https://app.acme-corp.test"


@pytest.fixture
def ready(lead):
    item = engagement_service.create_engagement(
        engagement_data(primary_target_url=f"{BASE}/", authorized_scope=["app.acme-corp.test"], excluded_scope=[f"{BASE}/private"]), lead
    )
    engagement_service.confirm_authorization(item, lead, "SOW-5", "CISO")
    engagement_service.transition(item, "active", lead)
    db.session.commit()
    library.seed_test_cases()
    return item


def workflow(engagement, actor, key="price_manipulation"):
    row = service.create_workflow(engagement, actor, key, "", f"{BASE}/shop", test_data_confirmed=True)
    db.session.commit()
    return row


def token(header: dict, claims: dict, signature: str = "c2ln") -> str:
    encode = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()  # noqa: E731
    return f"{encode(header)}.{encode(claims)}.{signature}"


def titles(result: dict) -> set[str]:
    return {issue["title"] for issue in result["issues"]}


class TestNoTargetTraffic:
    FORBIDDEN = {"socket", "http", "urllib.request", "requests", "httpx", "subprocess", "ssl", "app.mapping.client", "app.tools.runner"}

    @pytest.mark.parametrize(
        "relative",
        ["manual/analyzers.py", "manual/service.py", "manual/playbooks.py", "blueprints/manual/__init__.py",
         "blueprints/apitest/__init__.py", "findings/service.py", "findings/parsers.py"],
    )
    def test_module_has_no_network_or_process_imports(self, relative):
        tree = ast.parse((Path(app_package.__file__).parent / relative).read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {alias.name for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
        assert not {name for name in imported if name in self.FORBIDDEN or name.split(".")[0] in {"socket", "http", "subprocess", "ssl"}}


class TestWorkflows:
    def test_every_required_business_logic_area_has_a_playbook(self):
        assert set(PLAYBOOKS) == {
            "price_manipulation", "payment_bypass", "coupon_abuse", "transaction_replay", "race_condition",
            "duplicate_transaction", "workflow_bypass", "balance_manipulation", "reservation_manipulation",
            "unauthorized_modification",
        }

    def test_playbooks_reference_real_test_cases_and_have_expected_outcomes(self):
        ids = {case.test_id for case in wstg.CASES}
        for playbook in PLAYBOOKS.values():
            assert playbook.test_case in ids and playbook.remediation
            assert all(action and expected for action, expected in playbook.steps)

    def test_template_creates_steps(self, ready, lead):
        row = workflow(ready, lead)
        assert row.status == "draft" and len(row.steps) == len(PLAYBOOKS["price_manipulation"].steps)

    def test_test_data_confirmation_is_required(self, ready, lead):
        with pytest.raises(FindingError, match="test data"):
            service.create_workflow(ready, lead, "coupon_abuse", "", f"{BASE}/", test_data_confirmed=False)

    @pytest.mark.parametrize("url", ["https://evil.example.net/", f"{BASE}/private/a", "http://169.254.169.254/", ""])
    def test_target_must_be_in_scope(self, ready, lead, url):
        with pytest.raises(FindingError, match="scope"):
            service.create_workflow(ready, lead, "coupon_abuse", "", url, test_data_confirmed=True)

    def test_custom_workflow_with_tester_steps(self, ready, lead):
        row = service.create_workflow(ready, lead, "custom", "Loyalty points", f"{BASE}/points", test_data_confirmed=True)
        step = service.add_step(row, lead, "Redeem test points", "Balance decreases")
        assert row.steps == [step] and step.position == 1

    def test_status_follows_recorded_outcomes(self, ready, lead):
        row = workflow(ready, lead, "transaction_replay")
        service.record_step(row.steps[0], lead, "as_expected", "OK", "")
        assert row.status == "in_progress"
        for step in row.steps:
            service.record_step(step, lead, "as_expected", "OK", "")
        assert row.status == "passed"
        service.record_step(row.steps[1], lead, "blocked", "Sandbox offline", "")
        assert row.status == "blocked"
        service.record_step(row.steps[1], lead, "deviation", "Order processed twice", "")
        assert row.status == "failed"

    def test_deviation_needs_a_description(self, ready, lead):
        row = workflow(ready, lead)
        with pytest.raises(FindingError, match="actually happened"):
            service.record_step(row.steps[0], lead, "deviation", "", "")

    def test_evidence_is_redacted(self, ready, lead):
        row = workflow(ready, lead)
        service.record_step(row.steps[0], lead, "as_expected", "password=swordfish99", "Cookie: sid=TOPSECRET")
        assert "swordfish99" not in row.steps[0].actual_result and "TOPSECRET" not in row.steps[0].evidence

    def test_finding_requires_a_deviation(self, ready, lead):
        with pytest.raises(FindingError, match="deviation"):
            service.raise_workflow_finding(workflow(ready, lead), lead, "high")

    def test_raised_finding_is_linked_and_still_unconfirmed(self, ready, lead):
        row = workflow(ready, lead)
        service.record_step(row.steps[2], lead, "deviation", "Sandbox accepted the altered total", "Order 1001")
        finding = service.raise_workflow_finding(row, lead, "high")
        db.session.commit()
        assert finding.validation_status == "needs_manual_review" and finding.severity == "high"
        assert finding.test_case.test_id == "WSTG-BUSL-03" and finding.vulnerability_type == "business_logic"
        assert row.vulnerability_id == finding.id
        assert finding.evidence_items[0].origin == "tester" and "altered total" in finding.evidence_items[0].content
        with pytest.raises(FindingError, match="already"):
            service.raise_workflow_finding(row, lead, "high")


class TestAuthorizationMatrix:
    @pytest.fixture
    def matrix(self, ready, lead):
        user_a = service.add_subject(ready, lead, "User A", "Customer", "vault://client/user-a")
        user_b = service.add_subject(ready, lead, "User B", "Customer", "")
        check = service.add_check(ready, lead, "GET", f"{BASE}/invoices/100", "Invoice owned by User A")
        db.session.commit()
        return ready, user_a, user_b, check

    @pytest.mark.parametrize("reference", ["hunter2", "admin:password", "https://x/y", "vault://has space"])
    def test_passwords_cannot_be_stored_as_references(self, ready, lead, reference):
        with pytest.raises(FindingError, match="reference"):
            service.add_subject(ready, lead, "User C", "", reference)

    def test_resource_must_be_in_scope(self, ready, lead):
        with pytest.raises(FindingError, match="scope"):
            service.add_check(ready, lead, "GET", "https://evil.example.net/x", "")

    def test_violation_is_detected(self, matrix, lead):
        _, user_a, user_b, check = matrix
        allowed = service.record_result(check, user_a, lead, "allow", "allowed", "")
        violation = service.record_result(check, user_b, lead, "deny", "allowed", "Could read the invoice")
        assert not allowed.is_violation and violation.is_violation

    @pytest.mark.parametrize("expected,observed", [("deny", "denied"), ("deny", "untested"), ("allow", "denied"), ("deny", "error")])
    def test_other_results_are_not_violations(self, matrix, lead, expected, observed):
        _, _, user_b, check = matrix
        assert not service.record_result(check, user_b, lead, expected, observed, "").is_violation

    def test_invalid_values_are_refused(self, matrix, lead):
        _, _, user_b, check = matrix
        with pytest.raises(FindingError):
            service.record_result(check, user_b, lead, "maybe", "allowed", "")

    def test_subject_from_another_engagement_is_refused(self, matrix, lead):
        _, _, _, check = matrix
        other = engagement_service.create_engagement(engagement_data(name="Other"), lead)
        engagement_service.confirm_authorization(other, lead, "SOW", "CISO")
        subject = service.add_subject(other, lead, "Outsider", "", "")
        with pytest.raises(FindingError, match="another engagement"):
            service.record_result(check, subject, lead, "deny", "allowed", "")

    def test_finding_needs_a_violation(self, matrix, lead):
        with pytest.raises(FindingError, match="violation"):
            service.raise_authz_finding(matrix[3], lead, "high")

    def test_violation_becomes_an_unconfirmed_finding(self, matrix, lead):
        _, user_a, user_b, check = matrix
        service.record_result(check, user_a, lead, "allow", "allowed", "")
        service.record_result(check, user_b, lead, "deny", "allowed", "Could read the invoice")
        finding = service.raise_authz_finding(check, lead, "high")
        db.session.commit()
        assert finding.vulnerability_type == "broken_access_control" and finding.validation_status == "needs_manual_review"
        assert finding.test_case.test_id == "WSTG-ATHZ-02" and "User B" in finding.description
        assert "Could read the invoice" in finding.evidence_items[0].content

    def test_summary_counts_violations(self, matrix, lead):
        ready, _, user_b, check = matrix
        service.record_result(check, user_b, lead, "deny", "allowed", "")
        assert service.matrix_data(ready)["violations"] == 1


class TestJwtAnalyzer:
    NOW = 1_800_000_000

    def good(self):
        return token({"alg": "RS256"}, {"sub": "1", "iss": "a", "aud": "b", "iat": self.NOW, "exp": self.NOW + 900})

    def test_well_formed_token_has_no_issues(self):
        assert analyzers.analyze_jwt(self.good(), self.NOW)["issues"] == []

    def test_bearer_prefix_is_accepted(self):
        assert analyzers.analyze_jwt(f"Bearer {self.good()}", self.NOW)["claims"]["sub"] == "1"

    @pytest.mark.parametrize(
        "header,claims,title",
        [({"alg": "none"}, {"exp": NOW + 60}, "Token is unsigned"), ({"alg": "RS256"}, {}, "No expiry"),
         ({"alg": "RS256"}, {"iat": NOW, "exp": NOW + 90 * 86400}, "Long token lifetime"),
         ({"alg": "RS256"}, {"exp": NOW - 5}, "Token has expired"),
         ({"alg": "RS256", "jku": "https://x"}, {"exp": NOW + 60}, "Header carries a jku key source"),
         ({"alg": "RS256"}, {"exp": NOW + 60, "password": "x"}, "Sensitive data in token"),
         ({"alg": "RS256"}, {"exp": NOW + 60}, "No issuer claim")],
    )
    def test_weaknesses_are_reported(self, header, claims, title):
        assert title in titles(analyzers.analyze_jwt(token(header, claims), self.NOW))

    def test_sensitive_claims_are_masked_and_the_signature_is_not_returned(self):
        result = analyzers.analyze_jwt(token({"alg": "RS256"}, {"password": "swordfish", "exp": 1}, "SIGNATUREVALUE"), self.NOW)
        dumped = json.dumps(result)
        assert "swordfish" not in dumped and "SIGNATUREVALUE" not in dumped and "not verified" in result["signature"]

    @pytest.mark.parametrize("value", ["", "abc", "a.b", "a.b.c.d", "!!!.###.$$$", "e30", "W10.W10.x"])
    def test_invalid_tokens_are_refused(self, value):
        with pytest.raises(analyzers.AnalyzerError):
            analyzers.analyze_jwt(value)

    def test_oversized_input_is_refused(self):
        with pytest.raises(analyzers.AnalyzerError, match="64 KB"):
            analyzers.analyze_jwt("a" * (analyzers.MAX_INPUT + 1))


class TestHeaderAnalyzer:
    STRONG = ("HTTP/1.1 200 OK\nStrict-Transport-Security: max-age=31536000\nContent-Security-Policy: default-src 'self'; frame-ancestors 'none'\n"
              "X-Content-Type-Options: nosniff\nReferrer-Policy: no-referrer\nSet-Cookie: sid=abc; Secure; HttpOnly; SameSite=Lax")

    def test_hardened_response_has_no_issues(self):
        assert analyzers.analyze_headers(self.STRONG)["issues"] == []

    def test_missing_headers_are_reported(self):
        found = titles(analyzers.analyze_headers("HTTP/1.1 200 OK\nContent-Type: text/html"))
        assert {"HSTS is missing", "Content Security Policy is missing", "Framing is not restricted"} <= found

    @pytest.mark.parametrize(
        "line,title",
        [("Content-Security-Policy: script-src 'self' 'unsafe-inline'", "CSP allows inline script or style"),
         ("Content-Security-Policy: default-src *", "CSP allows scripts from any origin"),
         ("Strict-Transport-Security: max-age=60", "HSTS lifetime is short"),
         ("Server: Apache/2.4.49", "server reveals a version"),
         ("Set-Cookie: session=abc; Path=/", "Cookie session is missing attributes")],
    )
    def test_weak_values_are_reported(self, line, title):
        assert title in titles(analyzers.analyze_headers(f"HTTP/1.1 200 OK\n{line}"))

    def test_credentialed_wildcard_cors_is_high_severity(self):
        result = analyzers.analyze_headers("Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true")
        assert next(i for i in result["issues"] if i["title"] == "Unsafe CORS combination")["severity"] == "high"

    def test_text_without_headers_is_refused(self):
        with pytest.raises(analyzers.AnalyzerError):
            analyzers.analyze_headers("just some words")


class TestResponseComparison:
    def test_identical_access_is_flagged_for_review(self):
        message = "HTTP/1.1 200 OK\nContent-Type: text/html\n\nInvoice 100 total 50"
        result = analyzers.compare_responses(message, message)
        assert result["similarity"] == 100 and "nearly identical" in result["indicator"] and result["diff"] == []

    def test_different_status_is_reported(self):
        result = analyzers.compare_responses("HTTP/1.1 200 OK\n\nsecret data", "HTTP/1.1 403 Forbidden\n\ndenied")
        assert not result["same_status"] and "different status" in result["indicator"]

    def test_secrets_are_masked_in_the_diff(self):
        result = analyzers.compare_responses("HTTP/1.1 200 OK\n\npassword=alpha12345", "HTTP/1.1 200 OK\n\npassword=beta123456")
        assert "alpha12345" not in json.dumps(result) and "beta123456" not in json.dumps(result)

    def test_diff_output_is_bounded(self):
        left = "\n".join(f"a{i}" for i in range(1000))
        right = "\n".join(f"b{i}" for i in range(1000))
        result = analyzers.compare_responses(left, right)
        assert len(result["diff"]) == 200 and result["truncated"]


class TestPassiveReview:
    @pytest.fixture
    def collected(self, ready):
        page = Endpoint(engagement_id=ready.id, url="http://app.acme-corp.test/login", path="/login", in_scope=True)
        action = Endpoint(engagement_id=ready.id, url="http://app.acme-corp.test/session", path="/session", method="POST", in_scope=True)
        reset = Endpoint(engagement_id=ready.id, url=f"{BASE}/reset?token=REDACTED", path="/reset", in_scope=True)
        db.session.add_all([page, action, reset])
        db.session.flush()
        db.session.add_all([
            WebCookie(engagement_id=ready.id, endpoint_id=page.id, host="app.acme-corp.test", name="PHPSESSID", path="/"),
            WebCookie(engagement_id=ready.id, host="app.acme-corp.test", name="theme", path="/"),
            WebForm(engagement_id=ready.id, page_id=page.id, action_id=action.id, method="POST", fields=[], fields_fingerprint="a", has_password=True),
            EndpointParameter(engagement_id=ready.id, endpoint_id=reset.id, name="token", location="query"),
            Asset(engagement_id=ready.id, asset_type="certificate", value="app.acme-corp.test:443", in_scope=True,
                  attributes={"protocols": ["TLS 1.0", "TLS 1.3"], "expired": True, "weak_ciphers": []}),
        ])
        db.session.commit()
        return ready

    def run(self, engagement, actor):
        counters = service.run_passive_review(engagement, actor)
        db.session.commit()
        return counters

    def test_candidates_are_created_from_stored_data(self, collected, lead):
        self.run(collected, lead)
        types = {row.vulnerability_type for row in db.session.scalars(db.select(Vulnerability))}
        assert types == {"cookie_security", "cleartext_credentials", "csrf", "sensitive_query_parameter", "weak_tls"}

    def test_every_candidate_stays_unverified(self, collected, lead):
        self.run(collected, lead)
        assert {row.validation_status for row in db.session.scalars(db.select(Vulnerability))} == {"detected"}
        assert {item.origin for item in db.session.scalars(db.select(Evidence))} == {"import"}

    def test_passive_output_cannot_confirm_a_finding(self, collected, lead):
        self.run(collected, lead)
        row = db.session.scalar(db.select(Vulnerability))
        with pytest.raises(FindingError, match="your own validation evidence"):
            findings.transition(row, lead, "confirmed", "Passive review reported it.")

    def test_non_session_cookies_are_ignored(self, collected, lead):
        self.run(collected, lead)
        parameters = set(db.session.scalars(db.select(Vulnerability.parameter).filter_by(vulnerability_type="cookie_security")))
        assert parameters == {"PHPSESSID"}

    def test_review_is_repeatable(self, collected, lead):
        first = self.run(collected, lead)
        second = self.run(collected, lead)
        assert first.created_count == 5 and second.created_count == 0 and second.duplicate_count == 6 - 1

    def test_review_is_audited(self, collected, lead):
        self.run(collected, lead)
        assert db.session.scalar(db.select(ActivityLog).filter_by(action="manual.passive_review"))


class TestApiReview:
    def test_top_ten_is_complete(self, app):
        library.seed_test_cases()
        rows = db.session.scalars(db.select(TestCase).filter_by(category=api_top10.CATEGORY)).all()
        assert len(rows) == 10 and {row.framework_reference for row in rows} == {f"API{i}:2023" for i in range(1, 11)}
        assert all(row.validation_criteria and row.evidence_requirements and row.remediation_guidance for row in rows)

    def test_api_cases_do_not_change_wstg_coverage(self, ready):
        assert library.engagement_progress(ready)["total"] == 97

    def test_library_is_refreshed_after_an_upgrade(self, app):
        library.seed_test_cases()
        db.session.delete(db.session.scalar(db.select(TestCase).filter_by(category=api_top10.CATEGORY)))
        db.session.commit()
        library.ensure_library()
        assert db.session.scalar(db.select(db.func.count()).select_from(TestCase)) == 107

    @pytest.mark.parametrize(
        "path,category,content_type,style",
        [("/api/users", "api", "application/json", "REST"), ("/graphql", "graphql", "", "GraphQL"),
         ("/service.asmx", "api", "text/xml", "SOAP"), ("/ws/chat", "api", "", "WebSocket")],
    )
    def test_api_styles(self, path, category, content_type, style):
        from app.blueprints.apitest import api_style

        endpoint = Endpoint(url=f"{BASE}{path}", path=path, category=category, content_type=content_type)
        assert api_style(endpoint) == style

    def test_page_lists_routes_and_saves_reviews(self, client, login, ready):
        db.session.add(Endpoint(engagement_id=ready.id, url=f"{BASE}/api/v1/users", path="/api/v1/users", category="api", in_scope=True, requires_auth=False))
        db.session.add(Endpoint(engagement_id=ready.id, url="https://other.test/api/x", path="/api/x", category="api", in_scope=False))
        db.session.commit()
        login("lead.tester")
        body = client.get(f"/api-testing/?engagement={ready.id}").data
        assert b"/api/v1/users" in body and b"other.test" not in body and b"API1:2023" in body
        case = db.session.scalar(db.select(TestCase).filter_by(framework_reference="API1:2023"))
        assert client.post(f"/api-testing/engagements/{ready.id}/cases/{case.id}", data={"status": "passed", "notes": "Reviewed"}).status_code == 302
        assert db.session.scalar(db.select(TestExecution)).status == "passed"

    def test_wstg_case_cannot_be_updated_from_the_api_page(self, client, login, ready):
        case = db.session.scalar(db.select(TestCase).filter_by(test_id="WSTG-INFO-01"))
        login("lead.tester")
        assert client.post(f"/api-testing/engagements/{ready.id}/cases/{case.id}", data={"status": "passed"}).status_code == 404


class TestPages:
    def test_pages_render(self, client, login, ready, lead):
        row = workflow(ready, lead)
        service.add_subject(ready, lead, "User A", "", "")
        service.add_check(ready, lead, "GET", f"{BASE}/a", "")
        db.session.commit()
        login("lead.tester")
        for path in (f"/manual/?engagement={ready.id}", f"/manual/workflows/{row.id}", f"/manual/authorization?engagement={ready.id}",
                     f"/manual/analyzers?engagement={ready.id}", f"/manual/analyzers?engagement={ready.id}&tool=jwt",
                     f"/manual/analyzers?engagement={ready.id}&tool=compare", f"/manual/passive?engagement={ready.id}",
                     f"/api-testing/?engagement={ready.id}", "/methodology/library?category=APITOP10"):
            assert client.get(path).status_code == 200, path

    def test_workflow_through_the_ui(self, client, login, ready):
        login("lead.tester")
        response = client.post("/manual/workflows", data={"engagement": ready.id, "template": "coupon_abuse", "target_url": f"{BASE}/shop", "confirm": "y"})
        assert response.status_code == 302
        row = db.session.scalar(db.select(ManualWorkflow))
        step = row.steps[0]
        client.post(f"/manual/steps/{step.id}", data={"outcome": "deviation", "actual": "Coupon applied twice"})
        client.post(f"/manual/workflows/{row.id}/finding", data={"severity": "medium"})
        db.session.refresh(row)
        assert row.status == "failed" and row.vulnerability.validation_status == "needs_manual_review"

    def test_matrix_through_the_ui(self, client, login, ready):
        login("lead.tester")
        client.post("/manual/authorization/subjects", data={"engagement": ready.id, "label": "User B", "role": "Customer"})
        client.post("/manual/authorization/checks", data={"engagement": ready.id, "method": "GET", "url": f"{BASE}/invoices/1"})
        matrix = service.matrix_data(ready)
        check, subject = matrix["checks"][0], matrix["subjects"][0]
        client.post(f"/manual/authorization/checks/{check.id}/subjects/{subject.id}", data={"expected": "deny", "observed": "allowed"})
        assert b"Violation" in client.get(f"/manual/authorization?engagement={ready.id}").data
        client.post(f"/manual/authorization/checks/{check.id}/finding", data={"severity": "high"})
        db.session.refresh(check)
        assert check.vulnerability is not None

    def test_analyzer_results_never_echo_the_input(self, client, login, ready):
        login("lead.tester")
        value = token({"alg": "none"}, {"sub": "1"}, "UNIQUESIGNATURE")
        body = client.post(f"/manual/analyzers?engagement={ready.id}&tool=jwt", data={"token": value}).data
        assert b"Token is unsigned" in body and value.encode() not in body and b"UNIQUESIGNATURE" not in body

    def test_analysis_can_be_attached_as_tester_evidence(self, client, login, ready, lead):
        row = findings.create_manual_finding(ready, lead, {"name": "Weak token", "url": f"{BASE}/a"})
        db.session.commit()
        login("lead.tester")
        value = token({"alg": "none"}, {"sub": "1"}, "UNIQUESIGNATURE")
        client.post(f"/manual/analyzers?engagement={ready.id}&tool=jwt", data={"token": value, "finding": row.id})
        evidence = db.session.scalar(db.select(Evidence).filter_by(vulnerability_id=row.id))
        assert evidence.origin == "tester" and "UNIQUESIGNATURE" not in evidence.content

    def test_finding_from_another_engagement_cannot_receive_analysis(self, client, login, ready, lead):
        other = engagement_service.create_engagement(engagement_data(name="Other", primary_target_url=f"{BASE}/", authorized_scope=["app.acme-corp.test"], excluded_scope=[]), lead)
        engagement_service.confirm_authorization(other, lead, "SOW", "CISO")
        row = findings.create_manual_finding(other, lead, {"name": "Elsewhere", "url": f"{BASE}/a"})
        db.session.commit()
        login("lead.tester")
        response = client.post(f"/manual/analyzers?engagement={ready.id}&tool=headers", data={"headers": "Server: x", "finding": row.id})
        assert response.status_code == 404

    def test_passive_review_through_the_ui(self, client, login, ready):
        login("lead.tester")
        assert client.post(f"/manual/passive?engagement={ready.id}").status_code == 302

    def test_unassigned_user_gets_404(self, client, login, make_user, ready, lead):
        row = workflow(ready, lead)
        step = row.steps[0]
        subject = service.add_subject(ready, lead, "User A", "", "")
        check = service.add_check(ready, lead, "GET", f"{BASE}/a", "")
        db.session.commit()
        make_user("outsider")
        login("outsider")
        for path in (f"/manual/?engagement={ready.id}", f"/manual/workflows/{row.id}", f"/manual/authorization?engagement={ready.id}",
                     f"/manual/passive?engagement={ready.id}", f"/api-testing/?engagement={ready.id}"):
            assert client.get(path).status_code == 404, path
        for path, data in ((f"/manual/steps/{step.id}", {"outcome": "as_expected"}),
                           (f"/manual/authorization/checks/{check.id}/subjects/{subject.id}", {"expected": "deny", "observed": "denied"}),
                           (f"/manual/workflows/{row.id}/finding", {}), ("/manual/workflows", {"engagement": ready.id})):
            assert client.post(path, data=data).status_code == 404, path

    def test_read_only_role_can_view_but_not_change(self, client, login, make_user, ready, lead):
        row = workflow(ready, lead)
        viewer = make_user("client.view", "Client Viewer")
        ready.testers.append(viewer)
        db.session.commit()
        login("client.view")
        assert client.get(f"/manual/workflows/{row.id}").status_code == 200
        assert client.get(f"/manual/analyzers?engagement={ready.id}").status_code == 403
        assert client.post(f"/manual/steps/{row.steps[0].id}", data={"outcome": "as_expected"}).status_code == 403
        assert client.post(f"/manual/passive?engagement={ready.id}").status_code == 403

    def test_hostile_text_is_escaped(self, client, login, ready, lead):
        payload = "<script>alert(1)</script>"
        row = service.create_workflow(ready, lead, "custom", payload, f"{BASE}/a", payload, test_data_confirmed=True)
        service.add_step(row, lead, payload, payload)
        service.add_subject(ready, lead, payload, payload, "")
        service.add_check(ready, lead, "GET", f"{BASE}/b", payload)
        db.session.commit()
        login("lead.tester")
        for path in (f"/manual/?engagement={ready.id}", f"/manual/workflows/{row.id}", f"/manual/authorization?engagement={ready.id}"):
            body = client.get(path).data
            assert payload.encode() not in body and b"&lt;script&gt;" in body

    def test_archived_engagement_is_read_only(self, ready, lead):
        row = workflow(ready, lead)
        step: WorkflowStep = row.steps[0]
        ready.status = "archived"
        db.session.commit()
        with pytest.raises(FindingError, match="Archived"):
            service.record_step(step, lead, "as_expected", "", "")
        assert db.session.scalar(db.select(db.func.count()).select_from(AuthzCheck)) == 0
