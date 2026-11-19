"""Evidence repository: file uploads, secure storage, retrieval and retention.

Binary evidence (screenshots, captures) is stored on disk with owner-only permissions, outside the
web root, and served only through an access-controlled route. Image uploads are validated with
Pillow so a non-image cannot masquerade as one. Text evidence keeps the automatic secret redaction
from the findings service.
"""
from __future__ import annotations

import hashlib
import io
import os
import secrets
from datetime import timedelta
from pathlib import Path

from flask import current_app
from PIL import Image, UnidentifiedImageError
from werkzeug.utils import secure_filename

from app.extensions import db
from app.findings.service import FindingError, ensure_writable, redact_evidence
from app.models import Engagement, Evidence, User, Vulnerability, utcnow
from app.services import audit

# Extension -> stored MIME type. Only these may be uploaded.
IMAGE_TYPES = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp"}
TEXT_TYPES = {".txt": "text/plain", ".log": "text/plain", ".json": "application/json", ".har": "application/json", ".csv": "text/csv", ".md": "text/plain"}
ALLOWED_TYPES = {**IMAGE_TYPES, **TEXT_TYPES}
_PILLOW_FORMATS = {"PNG": "image/png", "JPEG": "image/jpeg", "GIF": "image/gif", "WEBP": "image/webp"}
MAX_IMAGE_PIXELS = 50_000_000  # Guards against decompression-bomb images.


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_image(data: bytes, extension: str) -> str:
    """Confirm the bytes are a real image and return the MIME type its content proves."""
    try:
        with Image.open(io.BytesIO(data)) as image:
            fmt = image.format
            width, height = image.size
            image.verify()
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise FindingError("That file is not a readable image.") from exc
    if fmt not in _PILLOW_FORMATS:
        raise FindingError("Only PNG, JPEG, GIF and WebP images are accepted.")
    if width * height > MAX_IMAGE_PIXELS:
        raise FindingError("The image resolution is too large.")
    return _PILLOW_FORMATS[fmt]


def _store(engagement_id: int, data: bytes) -> Path:
    directory = Path(current_app.config["EVIDENCE_DIR"]) / str(engagement_id)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / f"{secrets.token_hex(16)}.bin"
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
    return path


def _retention() -> object:
    days = current_app.config["EVIDENCE_RETENTION_DAYS"]
    return utcnow() + timedelta(days=days) if days > 0 else None


def add_file_evidence(
    vulnerability: Vulnerability, actor: User, title: str, filename: str, data: bytes, description: str = ""
) -> Evidence:
    """Store an uploaded file as evidence for a finding. The caller commits."""
    ensure_writable(vulnerability.engagement)
    title = (title or "").strip()
    if not title:
        raise FindingError("Give the evidence a title.")
    safe_name = secure_filename(filename or "")[:255]
    extension = Path(safe_name).suffix.lower()
    if not safe_name or extension not in ALLOWED_TYPES:
        raise FindingError("Upload a PNG, JPEG, GIF, WebP, text, log, JSON, HAR, CSV or Markdown file.")
    if not data:
        raise FindingError("The uploaded file is empty.")
    if len(data) > current_app.config["EVIDENCE_MAX_BYTES"]:
        raise FindingError("The file is too large.")

    is_image = extension in IMAGE_TYPES
    stored_content = None
    if is_image:
        mime_type = _validate_image(data, extension)
        evidence_type = "screenshot"
    else:
        try:
            text = redact_evidence(data.decode("utf-8-sig"))
        except UnicodeDecodeError as exc:
            raise FindingError("Text evidence must be UTF-8.") from exc
        # Store redacted text in the content column; the raw upload is not kept for text files.
        stored_content = text
        mime_type = TEXT_TYPES[extension]
        evidence_type = "log" if extension in (".log", ".txt", ".md") else "json"

    item = Evidence(
        engagement_id=vulnerability.engagement_id, vulnerability_id=vulnerability.id,
        test_case_id=vulnerability.test_case_id, tester_id=actor.id, evidence_type=evidence_type,
        origin="tester", title=title[:255], original_filename=safe_name, mime_type=mime_type,
        captured_at=utcnow(), retain_until=_retention(),
    )
    if is_image:
        path = _store(vulnerability.engagement_id, data)
        item.storage_path = str(path)
        item.sha256 = _sha256(data)
        item.size_bytes = len(data)
    else:
        item.content = stored_content
        item.sha256 = hashlib.sha256(stored_content.encode()).hexdigest()
        item.size_bytes = len(stored_content.encode())
    db.session.add(item)
    db.session.flush()
    audit.record(
        "evidence.uploaded", engagement_id=vulnerability.engagement_id, object_type="finding",
        object_id=vulnerability.finding_uid, details={"evidence_id": item.id, "type": evidence_type, "sha256": item.sha256},
        actor=actor,
    )
    return item


def evidence_file_path(item: Evidence) -> Path:
    """Return the on-disk path of a stored binary evidence file, rejecting anything outside the store."""
    if not item.storage_path:
        raise FindingError("This evidence has no stored file.")
    root = Path(current_app.config["EVIDENCE_DIR"]).resolve()
    path = Path(item.storage_path).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise FindingError("The evidence file is missing.")
    return path


def delete_evidence(item: Evidence, actor: User) -> None:
    """Remove an evidence item and its stored file. The caller commits."""
    ensure_writable(item.engagement)
    uid = item.vulnerability.finding_uid if item.vulnerability else None
    if item.storage_path:
        try:
            evidence_file_path(item).unlink()
        except (FindingError, OSError):
            pass
    audit.record(
        "evidence.deleted", engagement_id=item.engagement_id, object_type="finding", object_id=uid,
        details={"evidence_id": item.id, "sha256": item.sha256}, actor=actor,
    )
    db.session.delete(item)


def engagement_evidence(engagement: Engagement):
    """Return every evidence item for an engagement, newest first."""
    return db.session.scalars(
        db.select(Evidence).filter_by(engagement_id=engagement.id).order_by(Evidence.id.desc())
    ).all()
