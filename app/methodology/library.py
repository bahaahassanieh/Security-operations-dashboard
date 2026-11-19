"""Test case library seeding and per-engagement methodology tracking."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import func

from app.extensions import db
from app.methodology import api_top10, wstg
from app.models import Engagement, Severity, TestCase, TestExecution, User, Vulnerability, utcnow
from app.models.testing import EXECUTION_MODES, EXECUTION_STATUSES
from app.services import audit

COMPLETE_STATUSES = ("passed", "failed", "not_applicable")

CUSTOM_FRAMEWORK = "Custom"
BUILTIN_FRAMEWORKS = {wstg.FRAMEWORK, api_top10.FRAMEWORK}
MAX_IMPORT = 2000
_TEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$")
_LONG = 20000


class MethodologyError(ValueError):
    """A user-correctable methodology problem."""


def seed_test_cases() -> int:
    """Create or refresh the versioned library. Engagement results are never touched. Commits."""
    existing = {row.test_id: row for row in db.session.scalars(db.select(TestCase))}
    catalogue = [(case, wstg.FRAMEWORK, wstg.FRAMEWORK_VERSION, f"WSTG-v42-{case.code}") for case in wstg.CASES]
    catalogue += [
        (case, api_top10.FRAMEWORK, api_top10.FRAMEWORK_VERSION, case.reference) for case in api_top10.CASES
    ]
    for case, framework, version, reference in catalogue:
        row = existing.get(case.test_id)
        if row is None:
            row = TestCase(test_id=case.test_id)
            db.session.add(row)
        row.framework = framework
        row.framework_version = version
        row.framework_reference = reference
        row.category = case.category
        row.title = case.title
        row.description = case.objective
        row.procedure = case.procedure
        row.required_tools = list(case.tools)
        row.expected_results = case.expected
        row.evidence_requirements = case.evidence
        row.default_severity = case.severity
        row.validation_criteria = case.validation
        row.remediation_guidance = case.remediation
        row.automation_level = case.automation
    db.session.commit()
    return len(catalogue)


def ensure_library() -> None:
    """Seed the library on first use, or after an upgrade adds test cases."""
    expected = len(wstg.CASES) + len(api_top10.CASES)
    if db.session.scalar(db.select(func.count()).select_from(TestCase)) < expected:
        seed_test_cases()


def engagement_progress(engagement: Engagement) -> dict:
    """Summarize methodology coverage overall and for each category."""
    cases = db.session.scalars(db.select(TestCase).filter_by(is_active=True, framework=wstg.FRAMEWORK)).all()
    executions = {
        row.test_case_id: row
        for row in db.session.scalars(db.select(TestExecution).filter_by(engagement_id=engagement.id))
    }
    categories = {
        code: {"code": code, "label": label, "total": 0, "complete": 0, "failed": 0}
        for code, label in wstg.CATEGORIES.items()
    }
    for case in cases:
        entry = categories[case.category]
        entry["total"] += 1
        execution = executions.get(case.id)
        if execution and execution.status in COMPLETE_STATUSES:
            entry["complete"] += 1
        if execution and execution.status == "failed":
            entry["failed"] += 1
    for entry in categories.values():
        entry["percent"] = round(100 * entry["complete"] / entry["total"]) if entry["total"] else 0
    total = len(cases)
    complete = sum(entry["complete"] for entry in categories.values())
    return {
        "total": total,
        "complete": complete,
        "failed": sum(entry["failed"] for entry in categories.values()),
        "percent": round(100 * complete / total) if total else 0,
        "categories": list(categories.values()),
        "executions": executions,
    }


def findings_per_case(engagement_id: int) -> dict[int, int]:
    """Count findings linked to each test case."""
    rows = db.session.execute(
        db.select(Vulnerability.test_case_id, func.count())
        .where(Vulnerability.engagement_id == engagement_id, Vulnerability.test_case_id.is_not(None))
        .group_by(Vulnerability.test_case_id)
    ).all()
    return dict(rows)


def update_execution(
    engagement: Engagement, case: TestCase, actor: User, status: str, notes: str
) -> TestExecution:
    """Record a tester's result for one test case. The caller commits."""
    if status not in EXECUTION_STATUSES:
        raise MethodologyError("Unknown test status.")
    if engagement.status == "archived":
        raise MethodologyError("Archived engagements cannot be changed.")
    row = db.session.scalar(
        db.select(TestExecution).filter_by(engagement_id=engagement.id, test_case_id=case.id)
    )
    if row is None:
        row = TestExecution(engagement_id=engagement.id, test_case_id=case.id, mode="manual")
        db.session.add(row)
    previous = row.status
    now = utcnow()
    if status != "not_started" and row.started_at is None:
        row.started_at = now
    row.completed_at = now if status in COMPLETE_STATUSES else None
    row.status = status
    row.notes = (notes or "").strip()[:5000]
    row.tester_id = actor.id
    db.session.flush()
    audit.record(
        "methodology.updated",
        engagement_id=engagement.id,
        object_type="test_case",
        object_id=case.test_id,
        details={"from": previous, "to": status},
        actor=actor,
    )
    return row


@dataclass
class ImportSummary:
    """The outcome of importing custom test cases."""

    created: int = 0
    updated: int = 0
    skipped: int = 0
    errors: list = field(default_factory=list)

    @property
    def changed(self) -> int:
        return self.created + self.updated


def _clean(value, limit: int) -> str:
    return str(value if value is not None else "").strip()[:limit]


def _validate_record(record, seen: set) -> str:
    """Validate one custom test case record and return its test_id, or raise MethodologyError."""
    if not isinstance(record, dict):
        raise MethodologyError("each test case must be a JSON object.")
    test_id = _clean(record.get("test_id"), 48)
    if not _TEST_ID.match(test_id):
        raise MethodologyError("test_id is missing or malformed (letters, digits, dot, dash, underscore; <= 48 chars).")
    if test_id in seen:
        raise MethodologyError(f"duplicate test_id {test_id} in the file.")
    seen.add(test_id)
    if not _clean(record.get("category"), 48):
        raise MethodologyError(f"{test_id}: category is required.")
    if not _clean(record.get("title"), 255):
        raise MethodologyError(f"{test_id}: title is required.")
    if (record.get("default_severity") or "info") not in Severity.ALL:
        raise MethodologyError(f"{test_id}: default_severity must be one of {', '.join(Severity.ALL)}.")
    if (record.get("automation_level") or "manual") not in EXECUTION_MODES:
        raise MethodologyError(f"{test_id}: automation_level must be one of {', '.join(EXECUTION_MODES)}.")
    if (_clean(record.get("framework"), 48) or CUSTOM_FRAMEWORK) in BUILTIN_FRAMEWORKS:
        raise MethodologyError(f"{test_id}: framework must not be a built-in framework name.")
    tools = record.get("required_tools")
    if tools is not None and not (isinstance(tools, list) and all(isinstance(item, str) for item in tools)):
        raise MethodologyError(f"{test_id}: required_tools must be a list of strings.")
    return test_id


def _apply_record(row: TestCase, record: dict, test_id: str) -> None:
    row.framework = _clean(record.get("framework"), 48) or CUSTOM_FRAMEWORK
    row.framework_version = _clean(record.get("framework_version"), 16)
    row.framework_reference = _clean(record.get("framework_reference"), 255) or test_id
    row.category = _clean(record.get("category"), 48)
    row.title = _clean(record.get("title"), 255)
    row.description = _clean(record.get("description"), _LONG)
    row.procedure = _clean(record.get("procedure"), _LONG)
    row.required_tools = [str(item)[:64] for item in (record.get("required_tools") or [])][:50]
    row.expected_results = _clean(record.get("expected_results"), _LONG)
    row.evidence_requirements = _clean(record.get("evidence_requirements"), _LONG)
    row.default_severity = record.get("default_severity") or "info"
    row.validation_criteria = _clean(record.get("validation_criteria"), _LONG)
    row.remediation_guidance = _clean(record.get("remediation_guidance"), _LONG)
    row.automation_level = record.get("automation_level") or "manual"
    row.is_active = record.get("is_active", True) is not False


def import_test_cases(records, actor: User | None = None) -> ImportSummary:
    """Validate and upsert custom test cases. Built-in cases are never overwritten. Commits."""
    if not isinstance(records, list):
        raise MethodologyError('The file must be a list of test cases, or an object with a "test_cases" list.')
    if len(records) > MAX_IMPORT:
        raise MethodologyError(f"Too many test cases in one file (limit {MAX_IMPORT}).")
    summary = ImportSummary()
    existing = {row.test_id: row for row in db.session.scalars(db.select(TestCase))}
    seen: set = set()
    for index, record in enumerate(records, start=1):
        try:
            test_id = _validate_record(record, seen)
        except MethodologyError as exc:
            summary.errors.append(f"Entry {index}: {exc}")
            summary.skipped += 1
            continue
        row = existing.get(test_id)
        if row is not None and row.framework in BUILTIN_FRAMEWORKS:
            summary.errors.append(f"Entry {index}: {test_id} is a built-in test case and was left unchanged.")
            summary.skipped += 1
            continue
        is_new = row is None
        if is_new:
            row = TestCase(test_id=test_id)
            db.session.add(row)
            existing[test_id] = row
        _apply_record(row, record, test_id)
        summary.created += int(is_new)
        summary.updated += int(not is_new)
    db.session.flush()
    audit.record(
        "methodology.cases_imported", object_type="test_case_library",
        details={"created": summary.created, "updated": summary.updated, "skipped": summary.skipped},
        actor=actor,
    )
    db.session.commit()
    return summary


def load_testcase_file(path) -> list:
    """Read a JSON (or YAML, if PyYAML is installed) file of custom test cases into a list."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise MethodologyError(f"Cannot read {path}: {exc}") from exc
    if path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml  # Optional; only needed for YAML files.
        except ImportError as exc:
            raise MethodologyError("Install PyYAML to import YAML files, or provide JSON.") from exc
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise MethodologyError(f"The file is not valid YAML: {exc}") from exc
    else:
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise MethodologyError(f"The file is not valid JSON: {exc}") from exc
    if isinstance(data, dict):
        data = data.get("test_cases")
    if not isinstance(data, list):
        raise MethodologyError('Provide a list of test cases, or an object with a "test_cases" list.')
    return data


def record_automated_coverage(engagement: Engagement, test_ids, actor: User) -> int:
    """Mark the given test cases as covered by automation, without overriding a tester's own result.

    The caller commits. Cases already set by a tester are left untouched.
    """
    ids = [item for item in dict.fromkeys(test_ids)]
    if not ids:
        return 0
    cases = {row.test_id: row for row in db.session.scalars(db.select(TestCase).where(TestCase.test_id.in_(ids)))}
    executions = {
        row.test_case_id: row
        for row in db.session.scalars(db.select(TestExecution).filter_by(engagement_id=engagement.id))
    }
    note = f"Automated coverage on {utcnow().date().isoformat()}; confirm manually."
    changed = 0
    for case in cases.values():
        execution = executions.get(case.id)
        if execution is not None and execution.status != "not_started":
            continue
        if execution is None:
            execution = TestExecution(engagement_id=engagement.id, test_case_id=case.id)
            db.session.add(execution)
        execution.status = "in_progress"
        execution.mode = "automated"
        execution.notes = note
        execution.tester_id = actor.id if actor else None
        execution.started_at = utcnow()
        changed += 1
    db.session.flush()
    return changed
