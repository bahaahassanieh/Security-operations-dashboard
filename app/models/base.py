"""Shared model helpers and controlled vocabularies."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import CheckConstraint

from app.extensions import db


def utcnow() -> datetime:
    """Return the current UTC time as a naive datetime (portable across SQLite and PostgreSQL)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def enum_check(column: str, values: tuple[str, ...], name: str) -> CheckConstraint:
    """Build a CHECK constraint restricting ``column`` to ``values``."""
    quoted = ", ".join(f"'{value}'" for value in values)
    return CheckConstraint(f"{column} IN ({quoted})", name=name)


class TimestampMixin:
    """Adds audit timestamps to a model."""

    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class EngagementStatus:
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    ARCHIVED = "archived"
    ALL = (DRAFT, ACTIVE, PAUSED, COMPLETED, ARCHIVED)


class ScopeEntryType:
    DOMAIN = "domain"
    WILDCARD = "wildcard"
    IP = "ip"
    CIDR = "cidr"
    URL = "url"
    ALL = (DOMAIN, WILDCARD, IP, CIDR, URL)


class Severity:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    ALL = (CRITICAL, HIGH, MEDIUM, LOW, INFO)


class ValidationStatus:
    DETECTED = "detected"
    NEEDS_REVIEW = "needs_manual_review"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    REMEDIATED = "remediated"
    RETEST_FAILED = "retest_failed"
    ALL = (
        DETECTED,
        NEEDS_REVIEW,
        CONFIRMED,
        FALSE_POSITIVE,
        ACCEPTED_RISK,
        REMEDIATED,
        RETEST_FAILED,
    )
    UNCONFIRMED = (DETECTED, NEEDS_REVIEW)


class RetestStatus:
    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    PASSED = "passed"
    FAILED = "failed"
    ALL = (NOT_REQUIRED, PENDING, PASSED, FAILED)


class RemediationStatus:
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    VERIFIED = "verified"
    WONT_FIX = "wont_fix"
    ALL = (OPEN, IN_PROGRESS, RESOLVED, VERIFIED, WONT_FIX)
    DONE = (RESOLVED, VERIFIED)


class JobStatus:
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ALL = (QUEUED, RUNNING, PAUSED, COMPLETED, FAILED, CANCELLED)
    ACTIVE = (QUEUED, RUNNING, PAUSED)


class AuditOutcome:
    SUCCESS = "success"
    DENIED = "denied"
    FAILURE = "failure"
    ALL = (SUCCESS, DENIED, FAILURE)


TESTING_METHODS = {
    "passive_recon": "Passive reconnaissance",
    "active_recon": "Active reconnaissance",
    "port_scanning": "Port and service scanning",
    "content_discovery": "Directory and content discovery",
    "automated_scanning": "Automated vulnerability scanning",
    "authenticated_testing": "Authenticated testing",
    "injection_testing": "Injection testing (non-destructive payloads)",
    "external_callbacks": "Tests using external callbacks (SSRF / XXE)",
    "exploit_validation": "Controlled exploit validation",
    "manual_testing": "Manual testing",
}
