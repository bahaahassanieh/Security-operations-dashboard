"""Findings engine: import, correlation, manual entry, evidence and validation."""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit, urlunsplit

from flask import current_app
from werkzeug.utils import secure_filename

from app.extensions import db
from app.findings import parsers, taxonomy
from app.reporting import cvss
from app.models import (
    Asset,
    AuditOutcome,
    Endpoint,
    Engagement,
    Evidence,
    FindingImport,
    FindingSource,
    FindingStatusChange,
    RetestStatus,
    Severity,
    TestCase,
    User,
    ValidationStatus,
    Vulnerability,
    utcnow,
)
from app.recon import inventory
from app.services import audit
from app.services import engagements as engagement_service
from app.services.scope import ScopeError, ScopeEvaluator, parse_target

ALLOWED_EXTENSIONS = {".json", ".jsonl", ".xml", ".csv", ".txt"}
MIN_JUSTIFICATION = 10
_RANK = {level: index for index, level in enumerate(reversed(Severity.ALL))}
_SECRET_HEADER = re.compile(
    r"(?im)^((?:proxy-)?authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token)(\s*:\s*).*$"
)
_SECRET_PAIR = re.compile(
    r"(?i)\b(pass(?:word|wd)?|pwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|token|session(?:id)?)"
    r"(\"?\s*[=:]\s*\"?)([^\s&\"',;]+)"
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")

TRANSITIONS = {
    ValidationStatus.DETECTED: {
        ValidationStatus.NEEDS_REVIEW, ValidationStatus.CONFIRMED, ValidationStatus.FALSE_POSITIVE,
    },
    ValidationStatus.NEEDS_REVIEW: {
        ValidationStatus.CONFIRMED, ValidationStatus.FALSE_POSITIVE, ValidationStatus.ACCEPTED_RISK,
    },
    ValidationStatus.CONFIRMED: {
        ValidationStatus.ACCEPTED_RISK, ValidationStatus.REMEDIATED, ValidationStatus.FALSE_POSITIVE,
    },
    ValidationStatus.FALSE_POSITIVE: {ValidationStatus.NEEDS_REVIEW},
    ValidationStatus.ACCEPTED_RISK: {ValidationStatus.CONFIRMED, ValidationStatus.REMEDIATED},
    ValidationStatus.REMEDIATED: {ValidationStatus.RETEST_FAILED, ValidationStatus.NEEDS_REVIEW},
    ValidationStatus.RETEST_FAILED: {ValidationStatus.REMEDIATED, ValidationStatus.CONFIRMED},
}
_NEEDS_JUSTIFICATION = {
    ValidationStatus.CONFIRMED, ValidationStatus.FALSE_POSITIVE, ValidationStatus.ACCEPTED_RISK,
    ValidationStatus.RETEST_FAILED,
}


class FindingError(ValueError):
    """A user-correctable findings problem."""


def redact_evidence(text: str) -> str:
    """Mask credentials and tokens before evidence is stored."""
    text = _SECRET_HEADER.sub(lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]", text or "")
    text = _BEARER.sub("Bearer [REDACTED]", text)
    text = _JWT.sub("[REDACTED-JWT]", text)
    return _SECRET_PAIR.sub(lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]", text)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def evidence_fingerprint(text: str) -> str:
    """Fingerprint evidence so re-uploads of the same detection are recognized."""
    normalized = " ".join((text or "").split())
    return _sha256(normalized) if normalized else ""


def endpoint_key(url: str) -> str:
    """Identify the affected resource, ignoring query values and letter case in the host."""
    canonical = inventory.canonical_url(url)
    parts = urlsplit(canonical)
    if parts.scheme in ("http", "https"):
        return urlunsplit((parts.scheme, parts.netloc, parts.path.rstrip("/") or "/", "", ""))
    return canonical.lower()


def dedup_fingerprint(type_key: str, url: str, parameter: str) -> str:
    """Correlate detections of the same weakness at the same location."""
    return _sha256(json.dumps([type_key, endpoint_key(url), (parameter or "").strip().lower()]))


def ensure_writable(engagement: Engagement) -> None:
    """Results belong only to engagements with a recorded authorization that are still open."""
    if engagement.status == "archived":
        raise FindingError("Archived engagements cannot be changed.")
    if not engagement.is_authorized:
        raise FindingError("Record client authorization for this engagement first.")


def is_in_scope(engagement: Engagement, url: str) -> bool:
    """Check a URL against the engagement's scope without any network activity."""
    return _is_in_scope(engagement_service.build_evaluator(engagement), url)


def _is_in_scope(evaluator: ScopeEvaluator, url: str) -> bool:
    try:
        parse_target(url)
    except ScopeError:
        return False
    return evaluator.evaluate(url).allowed


@dataclass
class _Context:
    engagement: Engagement
    actor: User
    evaluator: ScopeEvaluator
    cases: dict[str, int]
    cache: dict[str, Vulnerability]
    finding_import: FindingImport | None = None


def _build_context(engagement: Engagement, actor: User, finding_import=None) -> _Context:
    cases = dict(db.session.execute(db.select(TestCase.test_id, TestCase.id)).all())
    return _Context(engagement, actor, engagement_service.build_evaluator(engagement), cases, {}, finding_import)


def _new_uid() -> str:
    return f"F-{secrets.token_hex(6).upper()}"


def _link_inventory(ctx: _Context, row: Vulnerability, url: str, method: str) -> None:
    """Attach the finding to the mapped endpoint and asset when they are known."""
    parts = urlsplit(inventory.canonical_url(url))
    query = db.select(Endpoint).filter_by(engagement_id=ctx.engagement.id, path=parts.path or "/")
    if method:
        query = query.filter_by(method=method)
    endpoint = db.session.scalar(query.order_by(Endpoint.id).limit(1))
    if endpoint is not None:
        row.endpoint_id = endpoint.id
        row.asset_id = endpoint.asset_id
    if row.asset_id is None and parts.scheme:
        origin = urlunsplit((parts.scheme, parts.netloc, "/", "", ""))
        row.asset_id = db.session.scalar(
            db.select(Asset.id).filter_by(engagement_id=ctx.engagement.id, asset_type="web_service", value=origin).limit(1)
        )


def _add_import_evidence(ctx: _Context, row: Vulnerability, item: parsers.NormalizedFinding) -> None:
    content = redact_evidence(item.evidence)
    db.session.add(
        Evidence(
            engagement_id=ctx.engagement.id, vulnerability=row, test_case_id=row.test_case_id,
            tester_id=ctx.actor.id, evidence_type="tool_output", origin="import",
            title=f"{item.source} detection output"[:255], content=content,
            sha256=_sha256(content), size_bytes=len(content.encode()),
        )
    )


def _create_finding(
    ctx: _Context, item: parsers.NormalizedFinding, key: str, fingerprint: str,
    *, status: str = ValidationStatus.DETECTED, note: str | None = None, actor_id: int | None = None,
) -> Vulnerability:
    type_key, klass = taxonomy.classify(item.name, item.cwe)
    url = inventory.redact_url(inventory.canonical_url(item.url))
    description = item.description
    if item.references:
        description = f"{description}\n\nReferences:\n" + "\n".join(item.references)
    row = Vulnerability(
        finding_uid=_new_uid(), engagement_id=ctx.engagement.id, endpoint_url=url,
        http_method=item.method or None, parameter=item.parameter or None, name=item.name,
        vulnerability_type=type_key, description=description.strip(), severity=item.severity,
        cvss_score=item.cvss_score, cvss_vector=item.cvss_vector,
        cwe_id=item.cwe or (klass.cwe if klass else None), owasp_category=klass.owasp if klass else None,
        test_case_id=ctx.cases.get(klass.wstg) if klass and klass.wstg else None,
        detection_source=item.source[:64], validation_status=status,
        evidence_fingerprint=fingerprint or None, dedup_fingerprint=key,
        remediation_guidance=item.remediation,
    )
    db.session.add(row)
    db.session.flush()
    _link_inventory(ctx, row, item.url, item.method)
    db.session.add(
        FindingStatusChange(
            vulnerability_id=row.id, actor_id=actor_id, to_status=row.validation_status,
            justification=note or f"Imported from {item.source}. Awaiting tester validation.",
        )
    )
    return row


def _add_source(ctx: _Context, row: Vulnerability, item: parsers.NormalizedFinding, fingerprint: str) -> None:
    db.session.add(
        FindingSource(
            vulnerability=row, finding_import=ctx.finding_import, source=item.source[:64],
            reported_name=item.name, reported_severity=item.severity, confidence=item.confidence[:32] or None,
            evidence_fingerprint=fingerprint,
        )
    )
    if item.evidence:
        _add_import_evidence(ctx, row, item)


def _merge(row: Vulnerability, item: parsers.NormalizedFinding) -> None:
    """Enrich an existing finding. A scanner can raise attention but can never validate anything."""
    unvalidated = row.validation_status in ValidationStatus.UNCONFIRMED
    if unvalidated and _RANK[item.severity] > _RANK[row.severity]:
        row.severity = item.severity
    row.description = row.description or item.description
    row.remediation_guidance = row.remediation_guidance or item.remediation
    row.cwe_id = row.cwe_id or item.cwe
    row.cvss_score = row.cvss_score if row.cvss_score is not None else item.cvss_score
    row.cvss_vector = row.cvss_vector or item.cvss_vector
    if row.validation_status == ValidationStatus.REMEDIATED:
        row.status_changes.append(
            FindingStatusChange(
                from_status=row.validation_status, to_status=ValidationStatus.NEEDS_REVIEW,
                justification=f"Detected again by {item.source} after being marked remediated.",
            )
        )
        row.validation_status = ValidationStatus.NEEDS_REVIEW


def _store_upload(engagement: Engagement, data: bytes) -> Path:
    directory = Path(current_app.config["IMPORT_DIR"]) / str(engagement.id)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / f"{secrets.token_hex(16)}.upload"
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
    return path


def _decode_upload(filename: str, data: bytes) -> tuple[str, str]:
    safe_name = secure_filename(filename or "")[:255]
    if not safe_name or Path(safe_name).suffix.lower() not in ALLOWED_EXTENSIONS:
        raise FindingError("Upload a .json, .jsonl, .xml, .csv or .txt report.")
    if not data.strip():
        raise FindingError("The uploaded file is empty.")
    if len(data) > current_app.config["IMPORT_MAX_BYTES"]:
        raise FindingError("The uploaded file is too large.")
    if b"\x00" in data:
        raise FindingError("The uploaded file is not a text report.")
    try:
        return safe_name, data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise FindingError("The report must be UTF-8 text.") from exc


def import_results(
    engagement: Engagement, actor: User, filename: str, data: bytes, file_format: str = "auto"
) -> FindingImport:
    """Import one results file atomically. Every finding starts unverified. The caller commits."""
    ensure_writable(engagement)
    safe_name, text = _decode_upload(filename, data)
    digest = hashlib.sha256(data).hexdigest()
    previous = db.session.scalar(db.select(FindingImport).filter_by(engagement_id=engagement.id, sha256=digest))
    if previous is not None:
        raise FindingError(f"This exact file was already imported as {previous.original_filename}.")
    if file_format != "auto" and file_format not in parsers.FORMATS:
        raise FindingError("Unsupported report format.")
    try:
        report = parsers.parse_report(text, file_format)
    except parsers.ReportError as exc:
        raise FindingError(str(exc)) from exc

    path = _store_upload(engagement, data)
    record = FindingImport(
        engagement_id=engagement.id, uploaded_by_id=actor.id, original_filename=safe_name,
        file_format=report.file_format, sha256=digest, size_bytes=len(data), storage_path=str(path),
        total_records=len(report.findings) + report.rejected, rejected_count=report.rejected,
    )
    try:
        db.session.add(record)
        db.session.flush()
        ctx = _build_context(engagement, actor, record)
        for item in report.findings:
            _import_one(ctx, record, item)
        audit.record(
            "findings.imported",
            engagement_id=engagement.id,
            object_type="finding_import",
            object_id=record.id,
            details={
                "file": safe_name, "format": record.file_format, "sha256": digest,
                "created": record.created_count, "merged": record.merged_count,
                "duplicates": record.duplicate_count, "rejected": record.rejected_count,
                "out_of_scope": record.out_of_scope_count,
            },
            actor=actor,
        )
        db.session.flush()
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return record


def import_normalized(engagement: Engagement, actor: User, items: list[parsers.NormalizedFinding]) -> SimpleNamespace:
    """Correlate findings produced inside the platform. All stay unverified. The caller commits."""
    ensure_writable(engagement)
    counters = SimpleNamespace(created_count=0, merged_count=0, duplicate_count=0, out_of_scope_count=0)
    ctx = _build_context(engagement, actor)
    for item in items:
        _import_one(ctx, counters, item)
    return counters


def _import_one(ctx: _Context, record, item: parsers.NormalizedFinding) -> None:
    if not _is_in_scope(ctx.evaluator, item.url):
        record.out_of_scope_count += 1  # Results for unauthorized targets are never stored.
        return
    type_key, _ = taxonomy.classify(item.name, item.cwe)
    key = dedup_fingerprint(type_key, item.url, item.parameter)
    fingerprint = evidence_fingerprint(redact_evidence(item.evidence))
    row = ctx.cache.get(key) or db.session.scalar(
        db.select(Vulnerability).filter_by(engagement_id=ctx.engagement.id, dedup_fingerprint=key)
    )
    if row is None:
        row = _create_finding(ctx, item, key, fingerprint)
        ctx.cache[key] = row
        _add_source(ctx, row, item, fingerprint)
        db.session.flush()
        record.created_count += 1
        return
    ctx.cache[key] = row
    known = any(
        source.source == item.source[:64] and source.evidence_fingerprint == fingerprint
        for source in row.sources
    )
    if known:
        record.duplicate_count += 1
        return
    _add_source(ctx, row, item, fingerprint)
    _merge(row, item)
    db.session.flush()
    record.merged_count += 1


def create_manual_finding(engagement: Engagement, actor: User, data: dict) -> Vulnerability:
    """Record a tester's own finding. It still needs evidence before it can be confirmed."""
    ensure_writable(engagement)
    url = (data.get("url") or "").strip()
    name = (data.get("name") or "").strip()
    if not name or not url:
        raise FindingError("A name and an affected URL are required.")
    if not _is_in_scope(engagement_service.build_evaluator(engagement), url):
        raise FindingError("The affected URL is outside the authorized scope.")
    item = parsers.NormalizedFinding(
        name=name[:255], severity=parsers.severity(data.get("severity")), url=url[:2048], source="manual",
        method=(data.get("method") or "").upper()[:10], parameter=(data.get("parameter") or "").strip()[:255],
        description=(data.get("description") or "").strip()[:parsers.MAX_TEXT],
        remediation=(data.get("remediation") or "").strip()[:parsers.MAX_TEXT],
        cwe=parsers.cwe_id(data.get("cwe")),
    )
    type_key, _ = taxonomy.classify(item.name, item.cwe)
    key = dedup_fingerprint(type_key, item.url, item.parameter)
    existing = db.session.scalar(db.select(Vulnerability).filter_by(engagement_id=engagement.id, dedup_fingerprint=key))
    if existing is not None:
        raise FindingError(f"This matches existing finding {existing.finding_uid}.")
    ctx = _build_context(engagement, actor)
    row = _create_finding(
        ctx, item, key, "", status=ValidationStatus.NEEDS_REVIEW,
        note="Entered manually by a tester.", actor_id=actor.id,
    )
    case_id = data.get("test_case_id")
    if case_id is not None and str(case_id).isdigit():
        case = db.session.get(TestCase, int(case_id))
        if case is not None:
            row.test_case_id = case.id
    _add_source(ctx, row, item, "")
    db.session.flush()
    audit.record(
        "finding.created", engagement_id=engagement.id, object_type="finding", object_id=row.finding_uid,
        details={"name": row.name, "severity": row.severity}, actor=actor,
    )
    return row


def update_details(row: Vulnerability, actor: User, data: dict) -> None:
    """Let a tester correct severity and scoring. The caller commits."""
    ensure_writable(row.engagement)
    score_text = (data.get("cvss_score") or "").strip()
    score = parsers.cvss_score(score_text) if score_text else None
    if score_text and score is None:
        raise FindingError("The CVSS score must be between 0 and 10.")
    vector_text = (data.get("cvss_vector") or "").strip()
    vector = parsers.cvss_vector(vector_text) if vector_text else None
    if vector_text and vector is None:
        raise FindingError("Enter a valid CVSS vector, such as CVSS:3.1/AV:N/AC:L/...")
    level = (data.get("severity") or "").lower()
    # A CVSS 3.1 vector computes its own score and severity, so they stay consistent.
    if vector and vector.startswith("CVSS:3.1"):
        try:
            computed = cvss.score_vector(vector)
        except cvss.CvssError as exc:
            raise FindingError(str(exc)) from exc
        score, level = computed.base_score, computed.severity if computed.severity != "none" else "info"
    if level not in Severity.ALL:
        raise FindingError("Choose a valid severity.")
    changes = {"severity": {"from": row.severity, "to": level}} if row.severity != level else {}
    row.severity, row.cvss_score, row.cvss_vector = level, score, vector
    row.remediation_guidance = (data.get("remediation") or "").strip()[:parsers.MAX_TEXT]
    audit.record(
        "finding.updated", engagement_id=row.engagement_id, object_type="finding", object_id=row.finding_uid,
        details=changes, actor=actor,
    )


def add_evidence(row: Vulnerability, actor: User, evidence_type: str, title: str, content: str) -> Evidence:
    """Attach a tester's validation evidence, masking secrets. The caller commits."""
    ensure_writable(row.engagement)
    if evidence_type not in ("http_capture", "tool_output", "comparison", "note", "log", "text", "json"):
        raise FindingError("Choose a valid evidence type.")
    title, content = (title or "").strip(), (content or "").strip()
    if not title or not content:
        raise FindingError("Evidence needs a title and content.")
    if len(content) > parsers.MAX_EVIDENCE:
        raise FindingError("Evidence is limited to 64 KB of text.")
    masked = redact_evidence(content)
    item = Evidence(
        engagement_id=row.engagement_id, vulnerability_id=row.id, test_case_id=row.test_case_id,
        tester_id=actor.id, evidence_type=evidence_type, origin="tester", title=title[:255], content=masked,
        sha256=_sha256(masked), size_bytes=len(masked.encode()),
    )
    db.session.add(item)
    db.session.flush()
    audit.record(
        "evidence.added", engagement_id=row.engagement_id, object_type="finding", object_id=row.finding_uid,
        details={"evidence_id": item.id, "type": evidence_type, "sha256": item.sha256}, actor=actor,
    )
    return item


def tester_evidence_count(row: Vulnerability) -> int:
    return sum(1 for item in row.evidence_items if item.origin == "tester")


def transition(row: Vulnerability, actor: User, new_status: str, justification: str) -> None:
    """Move a finding through validation. Confirmation always requires a tester's evidence."""
    ensure_writable(row.engagement)
    justification = (justification or "").strip()
    denial = None
    if new_status not in TRANSITIONS.get(row.validation_status, set()):
        denial = f"A finding cannot move from {row.validation_status} to {new_status}."
    elif new_status in _NEEDS_JUSTIFICATION and len(justification) < MIN_JUSTIFICATION:
        denial = f"Explain this decision in at least {MIN_JUSTIFICATION} characters."
    elif new_status == ValidationStatus.CONFIRMED and tester_evidence_count(row) == 0:
        denial = "Add your own validation evidence before confirming. Scanner output alone is not enough."
    if denial:
        audit.record(
            "finding.validation_denied", outcome=AuditOutcome.DENIED, engagement_id=row.engagement_id,
            object_type="finding", object_id=row.finding_uid, details={"to": new_status, "reason": denial}, actor=actor,
        )
        db.session.commit()
        raise FindingError(denial)
    previous = row.validation_status
    row.validation_status = new_status
    if new_status in (ValidationStatus.CONFIRMED, ValidationStatus.FALSE_POSITIVE):
        row.validated_by_id, row.validated_at = actor.id, utcnow()
    if new_status == ValidationStatus.REMEDIATED:
        row.retest_status = RetestStatus.PENDING
    elif new_status == ValidationStatus.RETEST_FAILED:
        row.retest_status = RetestStatus.FAILED
    row.status_changes.append(
        FindingStatusChange(actor_id=actor.id, from_status=previous, to_status=new_status, justification=justification[:5000])
    )
    audit.record(
        "finding.validated", engagement_id=row.engagement_id, object_type="finding", object_id=row.finding_uid,
        details={"from": previous, "to": new_status}, actor=actor,
    )
