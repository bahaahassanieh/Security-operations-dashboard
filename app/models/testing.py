"""Test case library, tool registry and execution tracking."""
from __future__ import annotations

from sqlalchemy import CheckConstraint

from app.extensions import db
from app.models.base import JobStatus, Severity, TimestampMixin, enum_check, utcnow

EXECUTION_STATUSES = ("not_started", "in_progress", "passed", "failed", "blocked", "not_applicable")
EXECUTION_MODES = ("automated", "semi_automated", "manual")
TOOL_HEALTH = ("unknown", "healthy", "degraded", "missing")
EVENT_LEVELS = ("info", "warning", "error")
TOOL_RUN_STATUSES = ("running", "completed", "failed", "timeout", "cancelled")


class TestCase(TimestampMixin, db.Model):
    """A methodology test case (OWASP WSTG, ASVS, API Top 10, ...)."""

    __test__ = False  # Not a pytest class.
    __tablename__ = "test_cases"
    __table_args__ = (
        enum_check("default_severity", Severity.ALL, "severity_valid"),
        enum_check("automation_level", EXECUTION_MODES, "automation_valid"),
    )

    id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(db.String(48), nullable=False, unique=True)
    framework = db.Column(db.String(48), nullable=False, index=True)
    framework_version = db.Column(db.String(16), nullable=False)
    framework_reference = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(48), nullable=False, index=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    procedure = db.Column(db.Text, nullable=False)
    required_tools = db.Column(db.JSON, nullable=False, default=list)
    expected_results = db.Column(db.Text, nullable=False)
    evidence_requirements = db.Column(db.Text, nullable=False)
    default_severity = db.Column(db.String(16), nullable=False, default=Severity.INFO)
    validation_criteria = db.Column(db.Text, nullable=False)
    remediation_guidance = db.Column(db.Text, nullable=False)
    automation_level = db.Column(db.String(16), nullable=False, default="manual")
    is_active = db.Column(db.Boolean, nullable=False, default=True)


class ExecutionJob(TimestampMixin, db.Model):
    """A background assessment job run by the orchestrator."""

    __tablename__ = "execution_jobs"
    __table_args__ = (
        enum_check("status", JobStatus.ALL, "status_valid"),
        CheckConstraint("progress BETWEEN 0 AND 100", name="progress_range"),
    )

    id = db.Column(db.Integer, primary_key=True)
    engagement_id = db.Column(
        db.Integer, db.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    requested_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    job_type = db.Column(db.String(48), nullable=False)
    status = db.Column(db.String(16), nullable=False, default=JobStatus.QUEUED, index=True)
    progress = db.Column(db.Integer, nullable=False, default=0)
    plan = db.Column(db.JSON, nullable=False, default=dict)
    queue_job_id = db.Column(db.String(64), index=True)
    cancel_requested = db.Column(db.Boolean, nullable=False, default=False)
    pause_requested = db.Column(db.Boolean, nullable=False, default=False)
    started_at = db.Column(db.DateTime)
    finished_at = db.Column(db.DateTime)
    error_message = db.Column(db.Text)

    engagement = db.relationship("Engagement")
    requested_by = db.relationship("User")
    events = db.relationship(
        "JobEvent", cascade="all, delete-orphan", order_by="JobEvent.id", lazy="dynamic"
    )
    tool_runs = db.relationship(
        "ToolRun", cascade="all, delete-orphan", order_by="ToolRun.id", lazy="dynamic"
    )


class JobEvent(db.Model):
    """One line of a job's execution log."""

    __tablename__ = "job_events"
    __table_args__ = (enum_check("level", EVENT_LEVELS, "level_valid"),)

    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(
        db.Integer, db.ForeignKey("execution_jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    level = db.Column(db.String(8), nullable=False, default="info")
    module = db.Column(db.String(32))
    message = db.Column(db.String(1000), nullable=False)


class ToolRun(TimestampMixin, db.Model):
    """One invocation of a security tool, with its exact arguments and captured output."""

    __tablename__ = "tool_runs"
    __table_args__ = (enum_check("status", TOOL_RUN_STATUSES, "status_valid"),)

    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(
        db.Integer, db.ForeignKey("execution_jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tool_name = db.Column(db.String(64), nullable=False, index=True)
    module = db.Column(db.String(32), nullable=False)
    target = db.Column(db.String(2048))
    arguments = db.Column(db.JSON, nullable=False, default=list)
    status = db.Column(db.String(16), nullable=False, default="running", index=True)
    exit_code = db.Column(db.Integer)
    duration_ms = db.Column(db.Integer)
    output_path = db.Column(db.String(512))
    output_sha256 = db.Column(db.String(64))
    output_bytes = db.Column(db.Integer)
    error_output = db.Column(db.Text)


class TestExecution(TimestampMixin, db.Model):
    """The result of running one test case within an engagement."""

    __test__ = False  # Not a pytest class.
    __tablename__ = "test_executions"
    __table_args__ = (
        enum_check("status", EXECUTION_STATUSES, "status_valid"),
        enum_check("mode", EXECUTION_MODES, "mode_valid"),
        db.UniqueConstraint("engagement_id", "test_case_id", name="uq_test_execution_case"),
    )

    id = db.Column(db.Integer, primary_key=True)
    engagement_id = db.Column(
        db.Integer, db.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    test_case_id = db.Column(db.Integer, db.ForeignKey("test_cases.id"), nullable=False, index=True)
    job_id = db.Column(db.Integer, db.ForeignKey("execution_jobs.id", ondelete="SET NULL"), index=True)
    tester_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    status = db.Column(db.String(16), nullable=False, default="not_started", index=True)
    mode = db.Column(db.String(16), nullable=False, default="manual")
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    result_summary = db.Column(db.Text)
    notes = db.Column(db.Text)

    test_case = db.relationship("TestCase")
    tester = db.relationship("User")


class ToolRegistry(TimestampMixin, db.Model):
    """A security tool known to the platform and its detected state."""

    __tablename__ = "tool_registry"
    __table_args__ = (enum_check("health_status", TOOL_HEALTH, "health_valid"),)

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False, unique=True)
    display_name = db.Column(db.String(128), nullable=False)
    category = db.Column(db.String(48), nullable=False, index=True)
    version = db.Column(db.String(64))
    executable_path = db.Column(db.String(512))
    install_instructions = db.Column(db.Text, nullable=False, default="")
    supported_modules = db.Column(db.JSON, nullable=False, default=list)
    required_permissions = db.Column(db.JSON, nullable=False, default=list)
    configuration = db.Column(db.JSON, nullable=False, default=dict)
    health_status = db.Column(db.String(16), nullable=False, default="unknown", index=True)
    is_enabled = db.Column(db.Boolean, nullable=False, default=True)
    last_checked_at = db.Column(db.DateTime)
