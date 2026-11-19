"""Vulnerabilities, evidence, reports, remediation and retests."""
from __future__ import annotations

from sqlalchemy import CheckConstraint, UniqueConstraint

from app.extensions import db
from app.models.base import (
    RemediationStatus,
    RetestStatus,
    Severity,
    TimestampMixin,
    ValidationStatus,
    enum_check,
    utcnow,
)

EVIDENCE_TYPES = (
    "http_capture",
    "screenshot",
    "tool_output",
    "log",
    "json",
    "text",
    "comparison",
    "note",
)
REPORT_TYPES = (
    "executive",
    "technical",
    "reconnaissance",
    "attack_surface",
    "api_security",
    "asvs_compliance",
    "retest",
    "remediation",
)
REPORT_FORMATS = ("pdf", "html")
RETEST_RESULTS = ("pending", "passed", "failed", "inconclusive")
EVIDENCE_ORIGINS = ("tester", "import")


class Vulnerability(TimestampMixin, db.Model):
    """A normalized finding. Scanner output starts as ``detected`` and is never auto-confirmed."""

    __tablename__ = "vulnerabilities"
    __table_args__ = (
        UniqueConstraint("engagement_id", "dedup_fingerprint", name="uq_vulnerability_dedup"),
        enum_check("severity", Severity.ALL, "severity_valid"),
        enum_check("validation_status", ValidationStatus.ALL, "validation_valid"),
        enum_check("retest_status", RetestStatus.ALL, "retest_valid"),
        CheckConstraint("cvss_score IS NULL OR (cvss_score BETWEEN 0 AND 10)", name="cvss_range"),
        db.Index("ix_vulnerabilities_engagement_severity", "engagement_id", "severity"),
        db.Index("ix_vulnerabilities_engagement_validation", "engagement_id", "validation_status"),
    )

    id = db.Column(db.Integer, primary_key=True)
    finding_uid = db.Column(db.String(32), nullable=False, unique=True)
    engagement_id = db.Column(
        db.Integer, db.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id", ondelete="SET NULL"), index=True)
    endpoint_id = db.Column(db.Integer, db.ForeignKey("endpoints.id", ondelete="SET NULL"), index=True)
    test_case_id = db.Column(db.Integer, db.ForeignKey("test_cases.id", ondelete="SET NULL"), index=True)
    endpoint_url = db.Column(db.String(2048))
    http_method = db.Column(db.String(10))
    parameter = db.Column(db.String(255))
    name = db.Column(db.String(255), nullable=False, index=True)
    vulnerability_type = db.Column(db.String(96), nullable=False, index=True)
    description = db.Column(db.Text, nullable=False, default="")
    severity = db.Column(db.String(16), nullable=False, default=Severity.INFO, index=True)
    cvss_score = db.Column(db.Float)
    cvss_vector = db.Column(db.String(255))
    cwe_id = db.Column(db.String(16), index=True)
    owasp_category = db.Column(db.String(64), index=True)
    attack_technique = db.Column(db.String(32))
    detection_source = db.Column(db.String(64), nullable=False, default="manual")
    detected_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    validation_status = db.Column(
        db.String(24), nullable=False, default=ValidationStatus.DETECTED, index=True
    )
    validated_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    validated_at = db.Column(db.DateTime)
    evidence_fingerprint = db.Column(db.String(64))
    dedup_fingerprint = db.Column(db.String(64), nullable=False)
    remediation_guidance = db.Column(db.Text, nullable=False, default="")
    retest_status = db.Column(db.String(16), nullable=False, default=RetestStatus.NOT_REQUIRED)

    engagement = db.relationship("Engagement")
    test_case = db.relationship("TestCase")
    validated_by = db.relationship("User", foreign_keys=[validated_by_id])
    sources = db.relationship(
        "FindingSource", cascade="all, delete-orphan", order_by="FindingSource.id",
        back_populates="vulnerability",
    )
    evidence_items = db.relationship(
        "Evidence", cascade="all, delete-orphan", order_by="Evidence.id", back_populates="vulnerability",
    )
    status_changes = db.relationship(
        "FindingStatusChange", cascade="all, delete-orphan", order_by="FindingStatusChange.id",
    )
    remediation = db.relationship(
        "Remediation", uselist=False, cascade="all, delete-orphan", back_populates="vulnerability",
    )
    retests = db.relationship(
        "Retest", cascade="all, delete-orphan", order_by="Retest.id", back_populates="vulnerability",
    )


class FindingImport(TimestampMixin, db.Model):
    """One uploaded results file from an automated engine."""

    __tablename__ = "finding_imports"
    __table_args__ = (UniqueConstraint("engagement_id", "sha256", name="uq_finding_import_file"),)

    id = db.Column(db.Integer, primary_key=True)
    engagement_id = db.Column(
        db.Integer, db.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    original_filename = db.Column(db.String(255), nullable=False)
    file_format = db.Column(db.String(24), nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False)
    storage_path = db.Column(db.String(512), nullable=False)
    total_records = db.Column(db.Integer, nullable=False, default=0)
    created_count = db.Column(db.Integer, nullable=False, default=0)
    merged_count = db.Column(db.Integer, nullable=False, default=0)
    duplicate_count = db.Column(db.Integer, nullable=False, default=0)
    rejected_count = db.Column(db.Integer, nullable=False, default=0)
    out_of_scope_count = db.Column(db.Integer, nullable=False, default=0)

    engagement = db.relationship("Engagement")
    uploaded_by = db.relationship("User")


class FindingSource(TimestampMixin, db.Model):
    """One tool's detection of a finding, kept so correlated detections stay traceable."""

    __tablename__ = "finding_sources"
    __table_args__ = (
        UniqueConstraint("vulnerability_id", "source", "evidence_fingerprint", name="uq_finding_source"),
    )

    id = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(
        db.Integer, db.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    import_id = db.Column(db.Integer, db.ForeignKey("finding_imports.id", ondelete="SET NULL"), index=True)
    source = db.Column(db.String(64), nullable=False, index=True)
    reported_name = db.Column(db.String(255), nullable=False)
    reported_severity = db.Column(db.String(16), nullable=False)
    confidence = db.Column(db.String(32))
    evidence_fingerprint = db.Column(db.String(64), nullable=False, default="")

    vulnerability = db.relationship("Vulnerability", back_populates="sources")
    finding_import = db.relationship("FindingImport")


class FindingStatusChange(db.Model):
    """The validation history of a finding."""

    __tablename__ = "finding_status_changes"

    id = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(
        db.Integer, db.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    from_status = db.Column(db.String(24))
    to_status = db.Column(db.String(24), nullable=False)
    justification = db.Column(db.Text, nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    actor = db.relationship("User")


class Evidence(TimestampMixin, db.Model):
    """An item in the evidence repository."""

    __tablename__ = "evidence"
    __table_args__ = (
        enum_check("evidence_type", EVIDENCE_TYPES, "evidence_type_valid"),
        enum_check("origin", EVIDENCE_ORIGINS, "origin_valid"),
    )

    id = db.Column(db.Integer, primary_key=True)
    engagement_id = db.Column(
        db.Integer, db.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    vulnerability_id = db.Column(
        db.Integer, db.ForeignKey("vulnerabilities.id", ondelete="SET NULL"), index=True
    )
    test_case_id = db.Column(db.Integer, db.ForeignKey("test_cases.id", ondelete="SET NULL"), index=True)
    tester_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    evidence_type = db.Column(db.String(24), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text)
    storage_path = db.Column(db.String(512))
    original_filename = db.Column(db.String(255))
    mime_type = db.Column(db.String(128))
    size_bytes = db.Column(db.Integer)
    sha256 = db.Column(db.String(64), index=True)
    is_sensitive = db.Column(db.Boolean, nullable=False, default=True)
    captured_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    retain_until = db.Column(db.DateTime, index=True)
    # Imported tool output can never, on its own, justify confirming a finding.
    origin = db.Column(db.String(16), nullable=False, default="tester", server_default="tester")

    vulnerability = db.relationship("Vulnerability", back_populates="evidence_items")
    tester = db.relationship("User")
    engagement = db.relationship("Engagement")


class Report(TimestampMixin, db.Model):
    """A generated report artifact."""

    __tablename__ = "reports"
    __table_args__ = (
        enum_check("report_type", REPORT_TYPES, "report_type_valid"),
        enum_check("output_format", REPORT_FORMATS, "format_valid"),
    )

    id = db.Column(db.Integer, primary_key=True)
    engagement_id = db.Column(
        db.Integer, db.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    generated_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    report_type = db.Column(db.String(24), nullable=False)
    output_format = db.Column(db.String(8), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    storage_path = db.Column(db.String(512), nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False, default=0)
    finding_count = db.Column(db.Integer, nullable=False, default=0)
    parameters = db.Column(db.JSON, nullable=False, default=dict)

    generated_by = db.relationship("User")
    engagement = db.relationship("Engagement")


class Remediation(TimestampMixin, db.Model):
    """Remediation tracking for a finding."""

    __tablename__ = "remediation"
    __table_args__ = (enum_check("status", RemediationStatus.ALL, "status_valid"),)

    id = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(
        db.Integer, db.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    owner = db.Column(db.String(160))
    status = db.Column(db.String(16), nullable=False, default=RemediationStatus.OPEN, index=True)
    due_date = db.Column(db.Date, index=True)
    resolved_at = db.Column(db.DateTime)
    notes = db.Column(db.Text)

    vulnerability = db.relationship("Vulnerability", back_populates="remediation")


class Retest(TimestampMixin, db.Model):
    """One retest attempt for a finding."""

    __tablename__ = "retests"
    __table_args__ = (enum_check("result", RETEST_RESULTS, "result_valid"),)

    id = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(
        db.Integer, db.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tester_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey("evidence.id", ondelete="SET NULL"), index=True)
    result = db.Column(db.String(16), nullable=False, default="pending", index=True)
    performed_at = db.Column(db.DateTime)
    notes = db.Column(db.Text)

    vulnerability = db.relationship("Vulnerability", back_populates="retests")
    tester = db.relationship("User")
    evidence = db.relationship("Evidence")


CWE_SOURCES = ("bundled", "imported")


class CweEntry(TimestampMixin, db.Model):
    """A CWE weakness reference: its description and a recommended testing procedure."""

    __tablename__ = "cwe_entries"
    __table_args__ = (enum_check("source", CWE_SOURCES, "source_valid"),)

    id = db.Column(db.Integer, primary_key=True)
    cwe_id = db.Column(db.String(16), nullable=False, unique=True, index=True)
    name = db.Column(db.String(255), nullable=False)
    abstraction = db.Column(db.String(16))
    description = db.Column(db.Text, nullable=False, default="")
    recommended_test = db.Column(db.Text, nullable=False, default="")
    mitigation = db.Column(db.Text, nullable=False, default="")
    url = db.Column(db.String(255), nullable=False, default="")
    source = db.Column(db.String(16), nullable=False, default="bundled")
