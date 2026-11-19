"""Business logic workflows, authorization comparison and passive review of collected data."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from app.extensions import db
from app.findings import parsers
from app.findings import service as findings
from app.findings.service import FindingError, ensure_writable, redact_evidence
from app.manual.playbooks import PLAYBOOKS
from app.models import (
    Asset,
    AuthzCheck,
    AuthzResult,
    AuthzSubject,
    Endpoint,
    EndpointParameter,
    Engagement,
    ManualWorkflow,
    TestCase,
    User,
    Vulnerability,
    WebCookie,
    WebForm,
    WorkflowStep,
    utcnow,
)
from app.models.manual import AUTHZ_EXPECTED, AUTHZ_OBSERVED, STEP_OUTCOMES
from app.recon import inventory
from app.services import audit
from app.services import engagements as engagement_service

_MAX_TEXT = 5000
_SESSION_COOKIE = re.compile(r"sess|sid|auth|token|jwt", re.I)
_SENSITIVE_PARAMETER = re.compile(r"pass|pwd|secret|token|api[_-]?key|session", re.I)
_DEPRECATED_PROTOCOLS = {"SSL 2", "SSL 3", "TLS 1.0", "TLS 1.1"}


def _text(value: str | None, limit: int = _MAX_TEXT) -> str:
    return redact_evidence((value or "").strip())[:limit]


def _require_scope(engagement: Engagement, url: str) -> str:
    url = (url or "").strip()
    if not url or not findings.is_in_scope(engagement, url):
        raise FindingError("The URL must be inside the engagement's authorized scope.")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise FindingError("Enter a full http:// or https:// URL.")
    return inventory.redact_url(inventory.canonical_url(url))[:2048]


def create_workflow(
    engagement: Engagement, actor: User, template_key: str, title: str, target_url: str, objective: str = "",
    *, test_data_confirmed: bool,
) -> ManualWorkflow:
    """Create a test plan from a playbook or from scratch. The caller commits."""
    ensure_writable(engagement)
    if not test_data_confirmed:
        raise FindingError("Confirm that this workflow will use test data and no real transactions.")
    playbook = PLAYBOOKS.get(template_key)
    if template_key != "custom" and playbook is None:
        raise FindingError("Choose a valid workflow template.")
    title = (title or "").strip() or (playbook.title if playbook else "")
    if not title:
        raise FindingError("Give the workflow a title.")
    workflow = ManualWorkflow(
        engagement_id=engagement.id, created_by_id=actor.id, template_key=template_key, title=title[:160],
        target_url=_require_scope(engagement, target_url),
        objective=_text(objective) or (playbook.objective if playbook else ""),
        preconditions=playbook.preconditions if playbook else "",
        test_data_confirmed=True,
    )
    for position, (action, expected) in enumerate(playbook.steps if playbook else (), start=1):
        workflow.steps.append(WorkflowStep(position=position, action=action, expected_result=expected))
    db.session.add(workflow)
    db.session.flush()
    audit.record(
        "manual.workflow_created", engagement_id=engagement.id, object_type="workflow", object_id=workflow.id,
        details={"template": template_key, "title": workflow.title}, actor=actor,
    )
    return workflow


def add_step(workflow: ManualWorkflow, actor: User, action: str, expected: str) -> WorkflowStep:
    """Add a tester-defined step. The caller commits."""
    ensure_writable(workflow.engagement)
    action, expected = _text(action), _text(expected)
    if not action or not expected:
        raise FindingError("A step needs an action and an expected result.")
    position = max((step.position for step in workflow.steps), default=0) + 1
    step = WorkflowStep(position=position, action=action, expected_result=expected)
    workflow.steps.append(step)
    _refresh_status(workflow)
    db.session.flush()
    return step


def _refresh_status(workflow: ManualWorkflow) -> None:
    outcomes = [step.outcome for step in workflow.steps]
    if "deviation" in outcomes:
        workflow.status = "failed"
    elif "blocked" in outcomes:
        workflow.status = "blocked"
    elif outcomes and all(item == "as_expected" for item in outcomes):
        workflow.status = "passed"
    elif any(item != "not_run" for item in outcomes):
        workflow.status = "in_progress"
    else:
        workflow.status = "draft"


def record_step(step: WorkflowStep, actor: User, outcome: str, actual: str, evidence: str) -> None:
    """Record what the tester observed. Secrets are masked. The caller commits."""
    workflow = step.workflow
    ensure_writable(workflow.engagement)
    if outcome not in STEP_OUTCOMES:
        raise FindingError("Choose a valid outcome.")
    actual, evidence = _text(actual), _text(evidence, findings.parsers.MAX_EVIDENCE)
    if outcome == "deviation" and not actual:
        raise FindingError("Describe what actually happened.")
    step.outcome, step.actual_result, step.evidence = outcome, actual, evidence
    step.tester_id, step.performed_at = actor.id, utcnow()
    _refresh_status(workflow)
    audit.record(
        "manual.step_recorded", engagement_id=workflow.engagement_id, object_type="workflow", object_id=workflow.id,
        details={"step": step.position, "outcome": outcome}, actor=actor,
    )


def _link_test_case(row: Vulnerability, test_id: str | None) -> None:
    if test_id:
        row.test_case_id = db.session.scalar(db.select(TestCase.id).filter_by(test_id=test_id)) or row.test_case_id


def raise_workflow_finding(workflow: ManualWorkflow, actor: User, severity: str) -> Vulnerability:
    """Turn recorded deviations into a finding that still needs validation. The caller commits."""
    if workflow.vulnerability_id:
        raise FindingError("A finding has already been raised for this workflow.")
    deviations = [step for step in workflow.steps if step.outcome == "deviation"]
    if not deviations:
        raise FindingError("Record a deviation before raising a finding.")
    playbook = PLAYBOOKS.get(workflow.template_key)
    row = findings.create_manual_finding(
        workflow.engagement, actor,
        {
            "name": f"Business logic flaw: {workflow.title}"[:255], "url": workflow.target_url, "severity": severity,
            "description": workflow.objective, "remediation": playbook.remediation if playbook else "",
        },
    )
    _link_test_case(row, playbook.test_case if playbook else "WSTG-BUSL-01")
    report = "\n\n".join(
        f"Step {step.position}: {step.action}\nExpected: {step.expected_result}\nActual: {step.actual_result}"
        + (f"\nEvidence:\n{step.evidence}" if step.evidence else "")
        for step in deviations
    )
    findings.add_evidence(row, actor, "comparison", "Workflow deviations", report[:parsers.MAX_EVIDENCE])
    workflow.vulnerability_id = row.id
    return row


def add_subject(engagement: Engagement, actor: User, label: str, role_name: str, reference: str) -> AuthzSubject:
    """Add a test account or role. Only a credential reference may be stored. The caller commits."""
    ensure_writable(engagement)
    label = (label or "").strip()[:80]
    if not label:
        raise FindingError("Give the test account a label.")
    reference = (reference or "").strip()
    if reference:
        try:
            engagement_service.parse_credential_references(f"{label} | {reference}")
        except engagement_service.EngagementError as exc:
            raise FindingError("Use a reference such as vault://client/user. Never enter a password.") from exc
    if db.session.scalar(db.select(AuthzSubject.id).filter_by(engagement_id=engagement.id, label=label)):
        raise FindingError("That label is already in use.")
    subject = AuthzSubject(
        engagement_id=engagement.id, label=label, role_name=(role_name or "").strip()[:80],
        credential_reference=reference or None,
    )
    db.session.add(subject)
    db.session.flush()
    audit.record("manual.subject_added", engagement_id=engagement.id, object_type="authz_subject", object_id=subject.id, details={"label": label}, actor=actor)
    return subject


def add_check(engagement: Engagement, actor: User, method: str, url: str, description: str) -> AuthzCheck:
    """Add a resource to compare across test accounts. The caller commits."""
    ensure_writable(engagement)
    url = _require_scope(engagement, url)
    method = re.sub(r"[^A-Z]", "", (method or "GET").upper())[:10] or "GET"
    if db.session.scalar(db.select(AuthzCheck.id).filter_by(engagement_id=engagement.id, method=method, url=url)):
        raise FindingError("That resource is already in the matrix.")
    endpoint_id = db.session.scalar(
        db.select(Endpoint.id).filter_by(engagement_id=engagement.id, method=method, url=url).limit(1)
    )
    check = AuthzCheck(
        engagement_id=engagement.id, endpoint_id=endpoint_id, method=method, url=url,
        description=_text(description, 255),
    )
    db.session.add(check)
    db.session.flush()
    audit.record("manual.check_added", engagement_id=engagement.id, object_type="authz_check", object_id=check.id, details={"method": method, "url": url}, actor=actor)
    return check


def record_result(check: AuthzCheck, subject: AuthzSubject, actor: User, expected: str, observed: str, notes: str) -> AuthzResult:
    """Record the tester's expected and observed access for one matrix cell. The caller commits."""
    if check.engagement_id != subject.engagement_id:
        raise FindingError("That test account belongs to another engagement.")
    engagement = db.session.get(Engagement, check.engagement_id)
    ensure_writable(engagement)
    if expected not in AUTHZ_EXPECTED or observed not in AUTHZ_OBSERVED:
        raise FindingError("Choose valid access values.")
    result = db.session.scalar(db.select(AuthzResult).filter_by(check_id=check.id, subject_id=subject.id))
    if result is None:
        result = AuthzResult(check_id=check.id, subject_id=subject.id)
        db.session.add(result)
    result.expected, result.observed, result.notes = expected, observed, _text(notes)
    result.tester_id, result.recorded_at = actor.id, utcnow()
    db.session.flush()
    audit.record(
        "manual.authz_recorded", engagement_id=check.engagement_id, object_type="authz_check", object_id=check.id,
        details={"subject": subject.label, "expected": expected, "observed": observed}, actor=actor,
    )
    return result


def raise_authz_finding(check: AuthzCheck, actor: User, severity: str) -> Vulnerability:
    """Turn a recorded access violation into a finding that still needs validation. The caller commits."""
    if check.vulnerability_id:
        raise FindingError("A finding has already been raised for this resource.")
    violations = [item for item in check.results if item.is_violation]
    if not violations:
        raise FindingError("Record an access violation before raising a finding.")
    engagement = db.session.get(Engagement, check.engagement_id)
    who = ", ".join(item.subject.label for item in violations)
    row = findings.create_manual_finding(
        engagement, actor,
        {
            "name": f"Broken access control: {check.method} {urlsplit(check.url).path or '/'}"[:255],
            "url": check.url, "method": check.method, "severity": severity,
            "description": f"{check.description}\n\nAccess that should be denied was observed for: {who}.".strip(),
            "remediation": "Enforce authorization on the server for every request, and deny access by default.",
        },
    )
    report = "\n\n".join(
        f"Test account: {item.subject.label} ({item.subject.role_name or 'no role recorded'})\n"
        f"Expected: {item.expected}\nObserved: {item.observed}\nNotes: {item.notes or 'None'}"
        for item in check.results
    )
    findings.add_evidence(row, actor, "comparison", "Authorization comparison", report[:parsers.MAX_EVIDENCE])
    check.vulnerability_id = row.id
    return row


def matrix_data(engagement: Engagement) -> dict:
    """Assemble the authorization matrix for display."""
    subjects = db.session.scalars(db.select(AuthzSubject).filter_by(engagement_id=engagement.id).order_by(AuthzSubject.id)).all()
    checks = db.session.scalars(db.select(AuthzCheck).filter_by(engagement_id=engagement.id).order_by(AuthzCheck.id)).all()
    cells = {(item.check_id, item.subject_id): item for check in checks for item in check.results}
    violations = sum(item.is_violation for item in cells.values())
    return {"subjects": subjects, "checks": checks, "cells": cells, "violations": violations}


def _passive_candidates(engagement: Engagement) -> list[parsers.NormalizedFinding]:
    """Derive review candidates from data already collected. No request is sent."""
    items: list[parsers.NormalizedFinding] = []

    def candidate(name, severity, url, description, *, parameter="", cwe=None, remediation=""):
        items.append(
            parsers.NormalizedFinding(
                name=name, severity=severity, url=url, source="passive_review", parameter=parameter, cwe=cwe,
                description=description, remediation=remediation, evidence=description, confidence="tentative",
            )
        )

    for cookie in db.session.scalars(db.select(WebCookie).filter_by(engagement_id=engagement.id)):
        if not _SESSION_COOKIE.search(cookie.name):
            continue
        missing = [label for flag, label in ((cookie.secure, "Secure"), (cookie.http_only, "HttpOnly"), (cookie.same_site, "SameSite")) if not flag]
        if missing:
            url = cookie.endpoint.url if cookie.endpoint else f"https://{cookie.host}/"
            candidate("Insecure cookie attributes", "medium" if len(missing) > 1 else "low", url,
                      f"Session cookie {cookie.name} is missing: {', '.join(missing)}.", parameter=cookie.name,
                      remediation="Set Secure, HttpOnly and SameSite on session cookies.")

    for form in db.session.scalars(db.select(WebForm).filter_by(engagement_id=engagement.id)):
        if form.has_password and form.action.url.startswith("http://"):
            candidate("Credentials submitted over unencrypted HTTP", "high", form.action.url,
                      f"The login form on {form.page.url} submits a password over HTTP.",
                      remediation="Serve login pages and their targets only over HTTPS.")
        if form.method == "POST" and not form.has_csrf_token:
            candidate("Form without a visible CSRF token", "medium", form.action.url,
                      f"The form on {form.page.url} has no recognizable anti-CSRF field. Check for other protections such as SameSite cookies.",
                      remediation="Use anti-CSRF tokens on state-changing forms.")

    rows = db.session.execute(
        db.select(EndpointParameter, Endpoint).join(Endpoint, EndpointParameter.endpoint_id == Endpoint.id)
        .where(EndpointParameter.engagement_id == engagement.id, EndpointParameter.location == "query", Endpoint.method == "GET")
    ).all()
    for parameter, endpoint in rows:
        if _SENSITIVE_PARAMETER.search(parameter.name):
            candidate("Sensitive parameter in URL query", "medium", endpoint.url,
                      f"The parameter {parameter.name} appears in a URL, where it can reach logs and browser history.",
                      parameter=parameter.name, remediation="Send sensitive values in the request body or a header.")

    for asset in db.session.scalars(
        db.select(Asset).filter_by(engagement_id=engagement.id, asset_type="web_service", in_scope=True)
    ):
        attrs = asset.attributes or {}
        status = attrs.get("status_code")
        headers = attrs.get("security_headers") or {}
        if not isinstance(status, int) or status >= 400:
            continue
        url = asset.value
        if url.startswith("https://") and not headers.get("strict_transport_security"):
            candidate("Missing HTTP Strict Transport Security", "low", url,
                      "The HTTPS service does not send a Strict-Transport-Security header.", cwe="CWE-319",
                      remediation="Send Strict-Transport-Security with a long max-age.")
        csp = headers.get("content_security_policy") or ""
        if not csp:
            candidate("Missing Content Security Policy", "low", url,
                      "No Content-Security-Policy response header is set.", cwe="CWE-693",
                      remediation="Define a Content Security Policy appropriate to the application.")
        if not headers.get("x_frame_options") and "frame-ancestors" not in csp.lower():
            candidate("Clickjacking protection missing", "medium", url,
                      "Neither X-Frame-Options nor a CSP frame-ancestors directive is set, so the page can be framed.",
                      cwe="CWE-1021", remediation="Set CSP frame-ancestors and X-Frame-Options.")
        if (headers.get("x_content_type_options") or "").lower() != "nosniff":
            candidate("Missing X-Content-Type-Options header", "low", url,
                      "The X-Content-Type-Options: nosniff header is not set.", cwe="CWE-693",
                      remediation="Set X-Content-Type-Options to nosniff.")

    for endpoint in db.session.scalars(
        db.select(Endpoint).filter_by(engagement_id=engagement.id, in_scope=True, status_code=200).limit(1000)
    ):
        if (endpoint.title or "").strip().lower().startswith("index of"):
            candidate("Directory listing enabled", "low", endpoint.url,
                      "The response title indicates an exposed directory listing.", cwe="CWE-548",
                      remediation="Disable directory listing and keep sensitive files outside the web root.")

    for endpoint in db.session.scalars(
        db.select(Endpoint).filter_by(engagement_id=engagement.id, in_scope=True)
        .where(Endpoint.requires_auth.is_(False), Endpoint.category.in_(("administration", "diagnostics"))).limit(500)
    ):
        candidate("Sensitive endpoint reachable without authentication",
                  "high" if endpoint.category == "administration" else "medium", endpoint.url,
                  f"A {endpoint.category} endpoint responded without requiring a sign-in.", cwe="CWE-306",
                  remediation="Require authentication and restrict administrative and diagnostic endpoints.")

    certificates = db.session.scalars(db.select(Asset).filter_by(engagement_id=engagement.id, asset_type="certificate", in_scope=True))
    for asset in certificates:
        details = asset.attributes or {}
        problems = [f"Deprecated protocol enabled: {item}" for item in details.get("protocols", []) if item in _DEPRECATED_PROTOCOLS]
        problems += [f"Weak cipher enabled: {item}" for item in details.get("weak_ciphers", [])[:10]]
        if details.get("expired"):
            problems.append("The certificate has expired.")
        if details.get("self_signed"):
            problems.append("The certificate is self-signed.")
        if problems:
            candidate("Weak TLS configuration", "medium", f"https://{asset.value}/", "\n".join(problems),
                      remediation="Allow only TLS 1.2 or newer with strong ciphers and a trusted, valid certificate.")
    return items


def run_passive_review(engagement: Engagement, actor: User):
    """Create unverified review candidates from stored data. The caller commits."""
    ensure_writable(engagement)
    counters = findings.import_normalized(engagement, actor, _passive_candidates(engagement))
    audit.record(
        "manual.passive_review", engagement_id=engagement.id, object_type="engagement", object_id=engagement.id,
        details={"created": counters.created_count, "merged": counters.merged_count, "unchanged": counters.duplicate_count},
        actor=actor,
    )
    return counters


def run_passive_findings(ctx) -> None:
    """Assessment-orchestrator step: turn already-collected data into unverified findings. Sends no traffic."""
    counters = run_passive_review(ctx.engagement, ctx.actor)
    db.session.commit()
    ctx.log(
        f"Passive review: {counters.created_count} new candidate(s), {counters.merged_count} correlated, "
        f"{counters.duplicate_count} unchanged. All stay unverified until a tester confirms them."
    )
