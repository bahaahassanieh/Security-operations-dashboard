"""Gather the data a report needs, straight from the database, for one engagement."""
from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import func

from app.extensions import db
from app.methodology import library as methodology
from app.models import (
    Asset,
    Endpoint,
    Engagement,
    Evidence,
    Remediation,
    Severity,
    Subdomain,
    Technology,
    ValidationStatus,
    Vulnerability,
)

# Findings a tester has acted on. These are the "confirmed" side of a report.
VALIDATED = (
    ValidationStatus.CONFIRMED, ValidationStatus.REMEDIATED, ValidationStatus.RETEST_FAILED,
    ValidationStatus.ACCEPTED_RISK,
)
UNVERIFIED = ValidationStatus.UNCONFIRMED  # detected, needs_manual_review
_SEVERITY_INDEX = {level: index for index, level in enumerate(Severity.ALL)}
SEVERITY_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}


def severity_sort(items, key=lambda row: row.severity):
    return sorted(items, key=lambda row: (_SEVERITY_INDEX.get(key(row), 99), row.id))


@dataclass
class ReportData:
    engagement: Engagement
    generated_at: str
    validated: list
    unverified: list
    severity_counts: dict
    status_counts: dict
    risk_score: int
    assets: dict
    technologies: list
    endpoints_sample: list
    api_routes: list
    remediation: list
    retests: list
    methodology: dict
    evidence_by_finding: dict
    options: dict = field(default_factory=dict)

    @property
    def validated_count(self) -> int:
        return len(self.validated)

    @property
    def highest_severity(self) -> str:
        return self.validated[0].severity if self.validated else "none"


def _counts(engagement_id: int, statuses) -> dict:
    rows = db.session.execute(
        db.select(Vulnerability.severity, func.count())
        .where(Vulnerability.engagement_id == engagement_id, Vulnerability.validation_status.in_(statuses))
        .group_by(Vulnerability.severity)
    ).all()
    return {level: 0 for level in Severity.ALL} | dict(rows)


def build(engagement: Engagement, options: dict | None = None) -> ReportData:
    """Assemble every figure a report could need for ``engagement``."""
    from app.models import utcnow

    options = options or {}
    eid = engagement.id
    findings = db.session.scalars(
        db.select(Vulnerability).filter_by(engagement_id=eid).order_by(Vulnerability.id)
    ).all()
    validated = severity_sort([f for f in findings if f.validation_status in VALIDATED])
    unverified = severity_sort([f for f in findings if f.validation_status in UNVERIFIED])

    severity_counts = _counts(eid, VALIDATED)
    status_counts = dict(
        db.session.execute(
            db.select(Vulnerability.validation_status, func.count())
            .filter_by(engagement_id=eid).group_by(Vulnerability.validation_status)
        ).all()
    )
    risk_score = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in validated)

    assets = {
        "subdomains": db.session.scalar(db.select(func.count()).select_from(Subdomain).filter_by(engagement_id=eid)) or 0,
        "in_scope_subdomains": db.session.scalar(db.select(func.count()).select_from(Subdomain).filter_by(engagement_id=eid, in_scope=True)) or 0,
        "services": db.session.scalar(db.select(func.count()).select_from(Asset).filter_by(engagement_id=eid, asset_type="web_service")) or 0,
        "endpoints": db.session.scalar(db.select(func.count()).select_from(Endpoint).filter_by(engagement_id=eid)) or 0,
    }
    technologies = db.session.scalars(
        db.select(Technology).filter_by(engagement_id=eid).order_by(Technology.name).limit(200)
    ).all()
    endpoints_sample = db.session.scalars(
        db.select(Endpoint).filter_by(engagement_id=eid, in_scope=True).order_by(Endpoint.url).limit(500)
    ).all()
    api_routes = db.session.scalars(
        db.select(Endpoint).filter_by(engagement_id=eid, in_scope=True)
        .where(Endpoint.category.in_(("api", "graphql"))).order_by(Endpoint.url).limit(300)
    ).all()
    remediation = db.session.scalars(
        db.select(Remediation).join(Vulnerability).where(Vulnerability.engagement_id == eid)
        .order_by(Remediation.status)
    ).all()
    retests = []
    for finding in validated:
        retests.extend(finding.retests)

    evidence_by_finding: dict[int, list] = {}
    if options.get("include_evidence"):
        rows = db.session.scalars(
            db.select(Evidence).filter_by(engagement_id=eid).where(Evidence.vulnerability_id.is_not(None)).order_by(Evidence.id)
        ).all()
        for item in rows:
            evidence_by_finding.setdefault(item.vulnerability_id, []).append(item)

    return ReportData(
        engagement=engagement,
        generated_at=utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        validated=validated,
        unverified=unverified,
        severity_counts=severity_counts,
        status_counts=status_counts,
        risk_score=risk_score,
        assets=assets,
        technologies=technologies,
        endpoints_sample=endpoints_sample,
        api_routes=api_routes,
        remediation=remediation,
        retests=retests,
        methodology=methodology.engagement_progress(engagement),
        evidence_by_finding=evidence_by_finding,
        options=options,
    )
