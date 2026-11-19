"""Tamper-evident audit logging.

Each record stores an HMAC over its content and the previous record's hash. Editing,
removing or reordering rows breaks the chain, and forging a row needs the HMAC key,
which is kept outside the database.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
from dataclasses import dataclass

from flask import current_app, g, has_request_context, request
from flask_login import current_user
from sqlalchemy import text

from app.extensions import db
from app.models import ActivityLog, AuditOutcome, utcnow

logger = logging.getLogger("ptp.audit")

GENESIS_HASH = "0" * 64
_SENSITIVE_KEY = re.compile(r"pass|secret|token|api[_-]?key|credential|cookie|session", re.I)


def redact(value):
    """Recursively mask values held under sensitive-looking keys."""
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if _SENSITIVE_KEY.search(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [redact(item) for item in value]
    return value


def _compute_hash(previous_hash: str, payload: dict) -> str:
    key = current_app.config["AUDIT_HMAC_KEY"]
    if not key:
        raise RuntimeError("AUDIT_HMAC_KEY is not configured.")
    message = previous_hash + json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


def _payload(entry: ActivityLog) -> dict:
    return {
        "timestamp": entry.timestamp.isoformat(timespec="microseconds"),
        "actor_id": entry.actor_id,
        "actor_name": entry.actor_name,
        "action": entry.action,
        "outcome": entry.outcome,
        "engagement_id": entry.engagement_id,
        "object_type": entry.object_type,
        "object_id": entry.object_id,
        "ip_address": entry.ip_address,
        "user_agent": entry.user_agent,
        "request_id": entry.request_id,
        "details": entry.details,
    }


def _lock_chain() -> None:
    """Serialize writers so two transactions can never extend the chain from the same head."""
    dialect = db.session.get_bind().dialect.name
    if dialect == "sqlite":
        # A zero-row write takes SQLite's single write lock for this transaction.
        db.session.execute(text("UPDATE application_settings SET key = key WHERE 1 = 0"))
    elif dialect == "postgresql":
        db.session.execute(text("SELECT pg_advisory_xact_lock(7239001)"))


def record(
    action: str,
    *,
    outcome: str = AuditOutcome.SUCCESS,
    engagement_id: int | None = None,
    object_type: str | None = None,
    object_id=None,
    details: dict | None = None,
    actor=None,
    actor_name: str | None = None,
) -> ActivityLog:
    """Add an audit entry to the current transaction. The caller commits."""
    db.session.flush()
    _lock_chain()

    if actor is None and has_request_context() and current_user.is_authenticated:
        actor = current_user._get_current_object()

    ip_address = user_agent = request_id = None
    if has_request_context():
        ip_address = request.remote_addr
        user_agent = (request.user_agent.string or "")[:255] or None
        request_id = g.get("request_id")

    previous = db.session.execute(
        db.select(ActivityLog.entry_hash).order_by(ActivityLog.id.desc()).limit(1)
    ).scalar()
    entry = ActivityLog(
        timestamp=utcnow(),
        actor_id=actor.id if actor else None,
        actor_name=(actor.username if actor else actor_name or "system")[:64],
        action=action,
        outcome=outcome,
        engagement_id=engagement_id,
        object_type=object_type,
        object_id=str(object_id) if object_id is not None else None,
        ip_address=ip_address,
        user_agent=user_agent,
        request_id=request_id,
        details=json.dumps(redact(details or {}), sort_keys=True, default=str),
        previous_hash=previous or GENESIS_HASH,
    )
    entry.entry_hash = _compute_hash(entry.previous_hash, _payload(entry))
    db.session.add(entry)
    db.session.flush()
    logger.info(
        "audit",
        extra={
            "event": action,
            "outcome": outcome,
            "actor": entry.actor_name,
            "engagement_id": engagement_id,
            "audit_id": entry.id,
            # An off-database anchor: truncating the newest rows cannot be hidden from this log.
            "entry_hash": entry.entry_hash,
        },
    )
    return entry


@dataclass(frozen=True)
class ChainStatus:
    """Result of verifying the audit chain."""

    valid: bool
    entries_checked: int
    first_broken_id: int | None = None
    message: str = "Audit chain is intact."


def verify_chain() -> ChainStatus:
    """Walk the chain from genesis and report the first inconsistency."""
    previous_hash = GENESIS_HASH
    previous_id = 0
    count = 0
    query = db.select(ActivityLog).order_by(ActivityLog.id).execution_options(yield_per=500)
    for entry in db.session.execute(query).scalars():
        if entry.id != previous_id + 1:
            return ChainStatus(
                False, count, entry.id, f"Entries missing before id {entry.id}."
            )
        if entry.previous_hash != previous_hash:
            return ChainStatus(False, count, entry.id, f"Chain link broken at id {entry.id}.")
        expected = _compute_hash(entry.previous_hash, _payload(entry))
        if not hmac.compare_digest(expected, entry.entry_hash):
            return ChainStatus(False, count, entry.id, f"Entry {entry.id} has been altered.")
        previous_hash = entry.entry_hash
        previous_id = entry.id
        count += 1
    return ChainStatus(True, count)
