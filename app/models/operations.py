"""Audit trail and application settings."""
from __future__ import annotations

from sqlalchemy import DDL, event

from app.extensions import db
from app.models.base import AuditOutcome, TimestampMixin, enum_check, utcnow

# Applied both here (create_all) and in the initial migration.
AUDIT_IMMUTABILITY_TRIGGERS = (
    """
    CREATE TRIGGER IF NOT EXISTS trg_activity_logs_no_update
    BEFORE UPDATE ON activity_logs
    BEGIN SELECT RAISE(ABORT, 'activity_logs is append-only'); END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_activity_logs_no_delete
    BEFORE DELETE ON activity_logs
    BEGIN SELECT RAISE(ABORT, 'activity_logs is append-only'); END
    """,
)


class ActivityLog(db.Model):
    """Append-only, HMAC hash-chained audit record."""

    __tablename__ = "activity_logs"
    __table_args__ = (
        enum_check("outcome", AuditOutcome.ALL, "outcome_valid"),
        db.Index("ix_activity_logs_engagement_time", "engagement_id", "timestamp"),
    )

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    actor_name = db.Column(db.String(64), nullable=False, default="system")
    action = db.Column(db.String(64), nullable=False, index=True)
    outcome = db.Column(db.String(16), nullable=False, default=AuditOutcome.SUCCESS, index=True)
    engagement_id = db.Column(db.Integer, db.ForeignKey("engagements.id"), index=True)
    object_type = db.Column(db.String(48))
    object_id = db.Column(db.String(64))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    request_id = db.Column(db.String(36))
    details = db.Column(db.Text, nullable=False, default="{}")
    previous_hash = db.Column(db.String(64), nullable=False)
    entry_hash = db.Column(db.String(64), nullable=False, unique=True)

    actor = db.relationship("User", foreign_keys=[actor_id])
    engagement = db.relationship("Engagement", foreign_keys=[engagement_id])


for _statement in AUDIT_IMMUTABILITY_TRIGGERS:
    event.listen(
        ActivityLog.__table__, "after_create", DDL(_statement).execute_if(dialect="sqlite")
    )


class ApplicationSetting(TimestampMixin, db.Model):
    """A typed, allow-listed runtime setting. See ``app.services.settings``."""

    __tablename__ = "application_settings"

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), nullable=False, unique=True)
    value = db.Column(db.String(255), nullable=False)
    updated_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
