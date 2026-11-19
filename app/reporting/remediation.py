"""Remediation tracking and retesting.

Retesting a finding is a tester action: the retest result and its evidence are recorded by hand, and
only a tester's decision can change a finding's validation status. A failed retest reopens the finding.
"""
from __future__ import annotations

from datetime import date, datetime

from app.extensions import db
from app.findings.service import FindingError, ensure_writable
from app.models import (
    Evidence,
    Remediation,
    RemediationStatus,
    Retest,
    RetestStatus,
    User,
    ValidationStatus,
    Vulnerability,
    utcnow,
)
from app.services import audit

RETEST_RESULTS = ("passed", "failed", "inconclusive")
# A finding may be retested once remediation has been claimed or it was already marked remediated.
RETESTABLE_STATUSES = {ValidationStatus.CONFIRMED, ValidationStatus.REMEDIATED, ValidationStatus.RETEST_FAILED, ValidationStatus.ACCEPTED_RISK}


def _parse_due(value: str | None) -> date | None:
    value = (value or "").strip()
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError as exc:
        raise FindingError("Enter the due date as YYYY-MM-DD.") from exc


def update_remediation(vulnerability: Vulnerability, actor: User, status: str, owner: str, due: str, notes: str) -> Remediation:
    """Create or update the remediation record for a finding. The caller commits."""
    ensure_writable(vulnerability.engagement)
    if status not in RemediationStatus.ALL:
        raise FindingError("Choose a valid remediation status.")
    record = vulnerability.remediation
    if record is None:
        record = Remediation()
        vulnerability.remediation = record
        db.session.add(record)
    previous = record.status
    record.status = status
    record.owner = (owner or "").strip()[:160] or None
    record.due_date = _parse_due(due)
    record.notes = (notes or "").strip()[:5000]
    record.resolved_at = utcnow() if status in RemediationStatus.DONE and record.resolved_at is None else (
        record.resolved_at if status in RemediationStatus.DONE else None
    )
    db.session.flush()
    audit.record(
        "remediation.updated", engagement_id=vulnerability.engagement_id, object_type="finding",
        object_id=vulnerability.finding_uid, details={"from": previous, "to": status}, actor=actor,
    )
    return record


def record_retest(vulnerability: Vulnerability, actor: User, result: str, notes: str, evidence_id: int | None) -> Retest:
    """Record a retest attempt and move the finding's status accordingly. The caller commits."""
    ensure_writable(vulnerability.engagement)
    if vulnerability.validation_status not in RETESTABLE_STATUSES:
        raise FindingError("Only a confirmed or remediated finding can be retested.")
    if result not in RETEST_RESULTS:
        raise FindingError("Choose a valid retest result.")
    notes = (notes or "").strip()[:5000]
    if result in ("failed", "inconclusive") and not notes:
        raise FindingError("Explain what you observed during the retest.")

    evidence = None
    if evidence_id:
        evidence = db.session.get(Evidence, evidence_id)
        if evidence is None or evidence.vulnerability_id != vulnerability.id:
            raise FindingError("Choose evidence that belongs to this finding.")
        if evidence.origin != "tester":
            raise FindingError("Retest evidence must be your own, not imported output.")

    retest = Retest(
        vulnerability_id=vulnerability.id, tester_id=actor.id, evidence_id=evidence.id if evidence else None,
        result=result, performed_at=utcnow(), notes=notes,
    )
    db.session.add(retest)

    previous = vulnerability.validation_status
    if result == "passed":
        vulnerability.validation_status = ValidationStatus.REMEDIATED
        vulnerability.retest_status = RetestStatus.PASSED
        if vulnerability.remediation is None:
            vulnerability.remediation = Remediation(status=RemediationStatus.VERIFIED, resolved_at=utcnow())
        else:
            vulnerability.remediation.status = RemediationStatus.VERIFIED
            vulnerability.remediation.resolved_at = vulnerability.remediation.resolved_at or utcnow()
    elif result == "failed":
        vulnerability.validation_status = ValidationStatus.RETEST_FAILED
        vulnerability.retest_status = RetestStatus.FAILED
        if vulnerability.remediation is not None:
            vulnerability.remediation.status = RemediationStatus.OPEN
            vulnerability.remediation.resolved_at = None
    else:
        vulnerability.retest_status = RetestStatus.PENDING

    db.session.flush()
    if previous != vulnerability.validation_status:
        from app.models import FindingStatusChange

        db.session.add(
            FindingStatusChange(
                vulnerability_id=vulnerability.id, actor_id=actor.id, from_status=previous,
                to_status=vulnerability.validation_status, justification=f"Retest {result}. {notes}"[:5000],
            )
        )
    audit.record(
        "retest.recorded", engagement_id=vulnerability.engagement_id, object_type="finding",
        object_id=vulnerability.finding_uid, details={"result": result, "status": vulnerability.validation_status}, actor=actor,
    )
    return retest


def retest_queue(engagement_id: int):
    """Findings that are ready for retesting, confirmed first."""
    order = db.case({status: index for index, status in enumerate(
        (ValidationStatus.RETEST_FAILED, ValidationStatus.CONFIRMED, ValidationStatus.REMEDIATED, ValidationStatus.ACCEPTED_RISK)
    )}, value=Vulnerability.validation_status, else_=99)
    return db.session.scalars(
        db.select(Vulnerability)
        .where(Vulnerability.engagement_id == engagement_id, Vulnerability.validation_status.in_(RETESTABLE_STATUSES))
        .order_by(order, Vulnerability.id)
    ).all()
