"""Dashboard metrics, always limited to the engagements the user may see."""
from __future__ import annotations

from sqlalchemy import case, func

from app.extensions import db
from app.models import (
    ActivityLog,
    Endpoint,
    Engagement,
    EngagementStatus,
    Remediation,
    RemediationStatus,
    Severity,
    Subdomain,
    User,
    ValidationStatus,
    Vulnerability,
)
from app.services.engagements import visible_engagements_query

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 6,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def _count(model, ids: list[int]) -> int:
    return db.session.scalar(
        db.select(func.count()).select_from(model).where(model.engagement_id.in_(ids))
    ) or 0


def build_summary(user: User) -> dict:
    """Assemble every dashboard metric for ``user``."""
    engagements = list(db.session.scalars(visible_engagements_query(user)))
    ids = [engagement.id for engagement in engagements]
    statuses = [engagement.status for engagement in engagements]

    severity_rows = db.session.execute(
        db.select(Vulnerability.severity, func.count())
        .where(
            Vulnerability.engagement_id.in_(ids),
            Vulnerability.validation_status != ValidationStatus.FALSE_POSITIVE,
        )
        .group_by(Vulnerability.severity)
    ).all()
    severity = {level: 0 for level in Severity.ALL} | dict(severity_rows)

    validation_rows = db.session.execute(
        db.select(Vulnerability.validation_status, func.count())
        .where(Vulnerability.engagement_id.in_(ids))
        .group_by(Vulnerability.validation_status)
    ).all()
    validation = {status: 0 for status in ValidationStatus.ALL} | dict(validation_rows)

    remediation_total, remediation_done = db.session.execute(
        db.select(
            func.count(Remediation.id),
            func.coalesce(
                func.sum(case((Remediation.status.in_(RemediationStatus.DONE), 1), else_=0)), 0
            ),
        )
        .join(Vulnerability, Remediation.vulnerability_id == Vulnerability.id)
        .where(Vulnerability.engagement_id.in_(ids))
    ).one()

    score = case(
        *[
            (Vulnerability.severity == level, weight)
            for level, weight in SEVERITY_WEIGHTS.items()
        ],
        else_=0,
    )
    vulnerable_rows = db.session.execute(
        db.select(
            Engagement.id,
            Engagement.name,
            Engagement.primary_target_url,
            func.count(Vulnerability.id),
            func.sum(score),
        )
        .join(Vulnerability, Vulnerability.engagement_id == Engagement.id)
        .where(
            Engagement.id.in_(ids),
            Vulnerability.validation_status != ValidationStatus.FALSE_POSITIVE,
        )
        .group_by(Engagement.id, Engagement.name, Engagement.primary_target_url)
        .order_by(func.sum(score).desc())
        .limit(5)
    ).all()

    activity_query = db.select(ActivityLog).order_by(ActivityLog.id.desc()).limit(10)
    if not user.has_permission("audit.view"):
        activity_query = activity_query.where(ActivityLog.engagement_id.in_(ids))
    activity = db.session.scalars(activity_query).all()

    unconfirmed = sum(validation[status] for status in ValidationStatus.UNCONFIRMED)
    return {
        "engagements": {
            "total": len(ids),
            "active": sum(
                status in (EngagementStatus.ACTIVE, EngagementStatus.PAUSED) for status in statuses
            ),
            "completed": sum(
                status in (EngagementStatus.COMPLETED, EngagementStatus.ARCHIVED)
                for status in statuses
            ),
            "draft": statuses.count(EngagementStatus.DRAFT),
        },
        "assets": {"domains": _count(Subdomain, ids), "endpoints": _count(Endpoint, ids)},
        "findings": {
            "total": sum(severity.values()),
            "severity": severity,
            "validation": validation,
            "confirmed": validation[ValidationStatus.CONFIRMED],
            "unconfirmed": unconfirmed,
            "false_positive": validation[ValidationStatus.FALSE_POSITIVE],
        },
        "remediation": {
            "total": remediation_total,
            "done": int(remediation_done),
            "percent": round(100 * int(remediation_done) / remediation_total)
            if remediation_total
            else 0,
        },
        "most_vulnerable": [
            {
                "id": row[0],
                "name": row[1],
                "target": row[2],
                "findings": row[3],
                "risk_score": int(row[4] or 0),
            }
            for row in vulnerable_rows
        ],
        "activity": [
            {
                "timestamp": entry.timestamp.isoformat(timespec="seconds") + "Z",
                "actor": entry.actor_name,
                "action": entry.action,
                "outcome": entry.outcome,
                "engagement_id": entry.engagement_id,
            }
            for entry in activity
        ],
    }
