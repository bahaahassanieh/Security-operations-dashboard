"""Generate, store and retrieve reports."""
from __future__ import annotations

import hashlib
import os
import secrets
from pathlib import Path

from flask import current_app

from app.extensions import db
from app.findings.service import FindingError
from app.models import Engagement, Report, User
from app.reporting import data as report_data
from app.reporting import render
from app.services import audit

REPORT_TYPES = tuple(render.REPORT_TITLES)
FORMATS = ("pdf", "html")


def _store(engagement_id: int, suffix: str, payload: bytes) -> Path:
    directory = Path(current_app.config["REPORT_DIR"]) / str(engagement_id)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / f"{secrets.token_hex(16)}.{suffix}"
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
    return path


def generate(engagement: Engagement, actor: User, report_type: str, output_format: str, options: dict) -> Report:
    """Build a report, store it and record it. The caller commits."""
    if report_type not in REPORT_TYPES:
        raise FindingError("Choose a valid report type.")
    if output_format not in FORMATS:
        raise FindingError("Choose PDF or HTML.")
    if not engagement.is_authorized:
        raise FindingError("Record client authorization before generating a report.")

    options = {
        "include_unverified": bool(options.get("include_unverified")),
        "include_evidence": bool(options.get("include_evidence")),
    }
    data = report_data.build(engagement, options)
    if output_format == "pdf":
        payload = render.render_pdf(report_type, data)
    else:
        payload = render.render_html(report_type, data).encode("utf-8")

    path = _store(engagement.id, output_format, payload)
    report = Report(
        engagement_id=engagement.id, generated_by_id=actor.id, report_type=report_type,
        output_format=output_format, title=f"{render.REPORT_TITLES[report_type]} — {engagement.name}"[:255],
        storage_path=str(path), sha256=hashlib.sha256(payload).hexdigest(), size_bytes=len(payload),
        finding_count=data.validated_count, parameters=options,
    )
    db.session.add(report)
    db.session.flush()
    audit.record(
        "report.generated", engagement_id=engagement.id, object_type="report", object_id=report.id,
        details={"type": report_type, "format": output_format, "findings": data.validated_count,
                 "sha256": report.sha256, **options},
        actor=actor,
    )
    return report


def report_file_path(report: Report) -> Path:
    """Return a report's on-disk path, rejecting anything outside the report store."""
    root = Path(current_app.config["REPORT_DIR"]).resolve()
    path = Path(report.storage_path).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise FindingError("The report file is missing.")
    return path


def delete_report(report: Report, actor: User) -> None:
    """Delete a report and its file. The caller commits."""
    try:
        report_file_path(report).unlink()
    except (FindingError, OSError):
        pass
    audit.record(
        "report.deleted", engagement_id=report.engagement_id, object_type="report", object_id=report.id,
        details={"sha256": report.sha256}, actor=actor,
    )
    db.session.delete(report)
