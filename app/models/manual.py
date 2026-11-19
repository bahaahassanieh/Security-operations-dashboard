"""Tester-driven workflows and authorization comparisons. Nothing here sends traffic to a target."""
from __future__ import annotations

from sqlalchemy import UniqueConstraint

from app.extensions import db
from app.models.base import TimestampMixin, enum_check, utcnow

WORKFLOW_STATUSES = ("draft", "in_progress", "passed", "failed", "blocked")
STEP_OUTCOMES = ("not_run", "as_expected", "deviation", "blocked")
AUTHZ_EXPECTED = ("allow", "deny")
AUTHZ_OBSERVED = ("untested", "allowed", "denied", "error")


class ManualWorkflow(TimestampMixin, db.Model):
    """A business logic test plan that a tester performs by hand."""

    __tablename__ = "manual_workflows"
    __table_args__ = (enum_check("status", WORKFLOW_STATUSES, "status_valid"),)

    id = db.Column(db.Integer, primary_key=True)
    engagement_id = db.Column(
        db.Integer, db.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerabilities.id", ondelete="SET NULL"), index=True)
    template_key = db.Column(db.String(48), nullable=False, default="custom")
    title = db.Column(db.String(160), nullable=False)
    target_url = db.Column(db.String(2048), nullable=False)
    objective = db.Column(db.Text, nullable=False, default="")
    preconditions = db.Column(db.Text, nullable=False, default="")
    status = db.Column(db.String(16), nullable=False, default="draft", index=True)
    test_data_confirmed = db.Column(db.Boolean, nullable=False, default=False)

    engagement = db.relationship("Engagement")
    created_by = db.relationship("User")
    vulnerability = db.relationship("Vulnerability")
    steps = db.relationship(
        "WorkflowStep", cascade="all, delete-orphan", order_by="WorkflowStep.position", back_populates="workflow"
    )


class WorkflowStep(TimestampMixin, db.Model):
    """One step of a workflow, with the expected and the observed outcome."""

    __tablename__ = "workflow_steps"
    __table_args__ = (
        UniqueConstraint("workflow_id", "position", name="uq_workflow_step_position"),
        enum_check("outcome", STEP_OUTCOMES, "outcome_valid"),
    )

    id = db.Column(db.Integer, primary_key=True)
    workflow_id = db.Column(
        db.Integer, db.ForeignKey("manual_workflows.id", ondelete="CASCADE"), nullable=False, index=True
    )
    position = db.Column(db.Integer, nullable=False)
    action = db.Column(db.Text, nullable=False)
    expected_result = db.Column(db.Text, nullable=False)
    actual_result = db.Column(db.Text, nullable=False, default="")
    evidence = db.Column(db.Text, nullable=False, default="")
    outcome = db.Column(db.String(16), nullable=False, default="not_run")
    tester_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    performed_at = db.Column(db.DateTime)

    workflow = db.relationship("ManualWorkflow", back_populates="steps")
    tester = db.relationship("User")


class AuthzSubject(TimestampMixin, db.Model):
    """A test account or role being compared. Only a reference to its credentials is stored."""

    __tablename__ = "authz_subjects"
    __table_args__ = (UniqueConstraint("engagement_id", "label", name="uq_authz_subject_label"),)

    id = db.Column(db.Integer, primary_key=True)
    engagement_id = db.Column(
        db.Integer, db.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    label = db.Column(db.String(80), nullable=False)
    role_name = db.Column(db.String(80), nullable=False, default="")
    credential_reference = db.Column(db.String(255))


class AuthzCheck(TimestampMixin, db.Model):
    """A protected resource or function to compare across subjects."""

    __tablename__ = "authz_checks"
    __table_args__ = (UniqueConstraint("engagement_id", "method", "url", name="uq_authz_check_resource"),)

    id = db.Column(db.Integer, primary_key=True)
    engagement_id = db.Column(
        db.Integer, db.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    endpoint_id = db.Column(db.Integer, db.ForeignKey("endpoints.id", ondelete="SET NULL"), index=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerabilities.id", ondelete="SET NULL"), index=True)
    method = db.Column(db.String(10), nullable=False, default="GET")
    url = db.Column(db.String(2048), nullable=False)
    description = db.Column(db.String(255), nullable=False, default="")

    results = db.relationship("AuthzResult", cascade="all, delete-orphan", back_populates="check")
    vulnerability = db.relationship("Vulnerability")


class AuthzResult(TimestampMixin, db.Model):
    """What a subject should be able to do with a resource, and what the tester observed."""

    __tablename__ = "authz_results"
    __table_args__ = (
        UniqueConstraint("check_id", "subject_id", name="uq_authz_result_cell"),
        enum_check("expected", AUTHZ_EXPECTED, "expected_valid"),
        enum_check("observed", AUTHZ_OBSERVED, "observed_valid"),
    )

    id = db.Column(db.Integer, primary_key=True)
    check_id = db.Column(db.Integer, db.ForeignKey("authz_checks.id", ondelete="CASCADE"), nullable=False, index=True)
    subject_id = db.Column(db.Integer, db.ForeignKey("authz_subjects.id", ondelete="CASCADE"), nullable=False, index=True)
    expected = db.Column(db.String(8), nullable=False, default="deny")
    observed = db.Column(db.String(8), nullable=False, default="untested")
    notes = db.Column(db.Text, nullable=False, default="")
    tester_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    recorded_at = db.Column(db.DateTime, default=utcnow)

    check = db.relationship("AuthzCheck", back_populates="results")
    subject = db.relationship("AuthzSubject")

    @property
    def is_violation(self) -> bool:
        return self.expected == "deny" and self.observed == "allowed"
