"""Engagements, their authorized scope and their targets."""
from __future__ import annotations

from sqlalchemy import CheckConstraint, UniqueConstraint

from app.extensions import db
from app.models.base import EngagementStatus, ScopeEntryType, TimestampMixin, enum_check, utcnow

engagement_testers = db.Table(
    "engagement_testers",
    db.Column(
        "engagement_id",
        db.Integer,
        db.ForeignKey("engagements.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    db.Column("user_id", db.Integer, db.ForeignKey("users.id"), primary_key=True, index=True),
)


class Engagement(TimestampMixin, db.Model):
    """A penetration testing engagement and its legal authorization record."""

    __tablename__ = "engagements"
    __table_args__ = (
        enum_check("status", EngagementStatus.ALL, "status_valid"),
        CheckConstraint("end_date >= start_date", name="dates_ordered"),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False, index=True)
    client_name = db.Column(db.String(160), nullable=False, index=True)
    description = db.Column(db.Text, nullable=False, default="")
    primary_target_url = db.Column(db.String(2048), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    rules_of_engagement = db.Column(db.Text, nullable=False, default="")
    authorized_methods = db.Column(db.JSON, nullable=False, default=list)
    credential_references = db.Column(db.JSON, nullable=False, default=list)
    status = db.Column(db.String(16), nullable=False, default=EngagementStatus.DRAFT, index=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    # Authorization record. Cleared whenever the authorized scope changes.
    authorization_reference = db.Column(db.String(255))
    authorization_signatory = db.Column(db.String(160))
    authorization_confirmed_at = db.Column(db.DateTime)
    authorization_confirmed_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    authorized_scope_fingerprint = db.Column(db.String(64))

    created_by = db.relationship("User", foreign_keys=[created_by_id])
    authorization_confirmed_by = db.relationship(
        "User", foreign_keys=[authorization_confirmed_by_id]
    )
    testers = db.relationship("User", secondary=engagement_testers, lazy="selectin")
    scope_entries = db.relationship(
        "EngagementScope",
        back_populates="engagement",
        cascade="all, delete-orphan",
        order_by="EngagementScope.id",
        lazy="selectin",
    )
    targets = db.relationship(
        "Target", back_populates="engagement", cascade="all, delete-orphan", order_by="Target.id"
    )

    @property
    def is_authorized(self) -> bool:
        return self.authorization_confirmed_at is not None

    @property
    def inclusions(self) -> list["EngagementScope"]:
        return [entry for entry in self.scope_entries if not entry.is_exclusion]

    @property
    def exclusions(self) -> list["EngagementScope"]:
        return [entry for entry in self.scope_entries if entry.is_exclusion]

    def within_window(self) -> bool:
        return self.start_date <= utcnow().date() <= self.end_date


class EngagementScope(TimestampMixin, db.Model):
    """One authorized or excluded scope rule. Exclusions always take precedence."""

    __tablename__ = "engagement_scope"
    __table_args__ = (
        UniqueConstraint(
            "engagement_id", "entry_type", "value", "is_exclusion", name="uq_scope_rule"
        ),
        enum_check("entry_type", ScopeEntryType.ALL, "entry_type_valid"),
    )

    id = db.Column(db.Integer, primary_key=True)
    engagement_id = db.Column(
        db.Integer, db.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    entry_type = db.Column(db.String(16), nullable=False)
    value = db.Column(db.String(2048), nullable=False)
    is_exclusion = db.Column(db.Boolean, nullable=False, default=False)

    engagement = db.relationship("Engagement", back_populates="scope_entries")


class Target(TimestampMixin, db.Model):
    """A concrete application under test, validated against scope when stored."""

    __tablename__ = "targets"
    __table_args__ = (UniqueConstraint("engagement_id", "url", name="uq_target_url"),)

    id = db.Column(db.Integer, primary_key=True)
    engagement_id = db.Column(
        db.Integer, db.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    url = db.Column(db.String(2048), nullable=False)
    host = db.Column(db.String(255), nullable=False, index=True)
    label = db.Column(db.String(160), nullable=False, default="")
    is_primary = db.Column(db.Boolean, nullable=False, default=False)

    engagement = db.relationship("Engagement", back_populates="targets")
