"""CWE reference: bundled seeding, official-catalog import, and lookups.

The catalog XML (format defined by the CWE schema) is parsed with defusedxml and matched by local
element name, so it is robust across CWE schema versions and safe against XXE and entity expansion.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree.ElementTree import ParseError  # nosec B405  Parsing uses defusedxml.

from defusedxml import ElementTree as SafeElementTree
from defusedxml.common import DefusedXmlException

from app.extensions import db
from app.models import CweEntry, TestCase, User
from app.reference.cwe_data import BUNDLED
from app.services import audit

CWE_FRAMEWORK = "CWE"
CWE_CATEGORY = "CWE"
CWE_CATEGORY_LABEL = "Common Weakness Enumeration"
MAX_WEAKNESSES = 5000
_MAX_TEXT = 8000
_CWE_ID = re.compile(r"(\d{1,7})")
_WS = re.compile(r"\s+")


class CweError(ValueError):
    """The CWE catalog file could not be read."""


@dataclass
class CweImportSummary:
    created: int = 0
    updated: int = 0
    skipped: int = 0
    errors: list = field(default_factory=list)

    @property
    def changed(self) -> int:
        return self.created + self.updated


def normalize_cwe_id(value) -> str | None:
    """Return a canonical ``CWE-<n>`` id, or ``None`` if the value holds no CWE number."""
    match = _CWE_ID.search(str(value or ""))
    return f"CWE-{int(match.group(1))}" if match else None


def cwe_url(cwe_id: str) -> str:
    number = normalize_cwe_id(cwe_id)
    return f"https://cwe.mitre.org/data/definitions/{number.split('-')[1]}.html" if number else "https://cwe.mitre.org/"


def _clean(text: str) -> str:
    return _WS.sub(" ", (text or "")).strip()[:_MAX_TEXT]


def _upsert_entry(existing: dict, cwe_id: str, source: str, **fields) -> bool:
    """Create or update a CweEntry. Returns True if newly created."""
    row = existing.get(cwe_id)
    is_new = row is None
    if is_new:
        row = CweEntry(cwe_id=cwe_id)
        db.session.add(row)
        existing[cwe_id] = row
    row.name = fields["name"][:255]
    row.abstraction = (fields.get("abstraction") or "")[:16] or None
    row.description = fields.get("description", "")
    row.recommended_test = fields.get("recommended_test", "")
    row.mitigation = fields.get("mitigation", "")
    row.url = cwe_url(cwe_id)
    row.source = source
    return is_new


def _seed_test_case(existing: dict, cwe_id: str, name: str, description: str, test: str, mitigation: str) -> None:
    row = existing.get(cwe_id)
    if row is None:
        row = TestCase(test_id=cwe_id)
        db.session.add(row)
        existing[cwe_id] = row
    row.framework = CWE_FRAMEWORK
    row.framework_version = ""
    row.framework_reference = cwe_id
    row.category = CWE_CATEGORY
    row.title = f"{cwe_id}: {name}"[:255]
    row.description = description or name
    row.procedure = test or "Test for this weakness using the recommended procedure for its category."
    row.required_tools = []
    row.expected_results = "The weakness is absent or adequately mitigated on the in-scope targets."
    row.evidence_requirements = "Request/response or configuration evidence demonstrating the weakness, with secrets redacted."
    row.default_severity = "info"
    row.validation_criteria = "A tester reproduces the weakness on an in-scope target and confirms its impact."
    row.remediation_guidance = mitigation or ""
    row.automation_level = "manual"


def seed_cwe(actor: User | None = None) -> tuple[int, int]:
    """Seed the bundled CWE reference and matching Test Case Library entries. Commits."""
    entries = {row.cwe_id: row for row in db.session.scalars(db.select(CweEntry))}
    cases = {row.test_id: row for row in db.session.scalars(db.select(TestCase).filter_by(framework=CWE_FRAMEWORK))}
    for cwe_id, (name, description, test, mitigation) in BUNDLED.items():
        # Do not downgrade an entry already enriched from the official catalog.
        if entries.get(cwe_id) is None or entries[cwe_id].source == "bundled":
            _upsert_entry(entries, cwe_id, "bundled", name=name, description=description,
                          recommended_test=test, mitigation=mitigation)
        _seed_test_case(cases, cwe_id, name, description, test, mitigation)
    db.session.commit()
    return len(BUNDLED), len(BUNDLED)


def ensure_cwe() -> None:
    """Seed the bundled CWE reference if it is missing (e.g. after an upgrade)."""
    if db.session.scalar(db.select(db.func.count()).select_from(CweEntry)) == 0:
        seed_cwe()


def cwe_for(cwe_id) -> CweEntry | None:
    """Return the CWE reference for a finding's CWE id, or ``None``."""
    normalized = normalize_cwe_id(cwe_id)
    if normalized is None:
        return None
    return db.session.scalar(db.select(CweEntry).filter_by(cwe_id=normalized))


# --- Official catalog import ----------------------------------------------

def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(element, name: str):
    return next((item for item in element if _local(item.tag) == name), None)


def _children(element, name: str):
    return [item for item in element if _local(item.tag) == name]


def _structured_text(element) -> str:
    """Flatten a CWE StructuredTextType (mixed XHTML) element to plain text."""
    return _clean("".join(element.itertext())) if element is not None else ""


def _detection_text(weakness) -> str:
    block = _child(weakness, "Detection_Methods")
    if block is None:
        return ""
    parts = []
    for method in _children(block, "Detection_Method"):
        name = (_child(method, "Method").text if _child(method, "Method") is not None else "") or ""
        description = _structured_text(_child(method, "Description"))
        parts.append(f"{name.strip()}: {description}".strip(": ").strip() if name else description)
    return "\n\n".join(part for part in parts if part)[:_MAX_TEXT]


def _mitigation_text(weakness) -> str:
    block = _child(weakness, "Potential_Mitigations")
    if block is None:
        return ""
    parts = []
    for mitigation in _children(block, "Mitigation"):
        description = _structured_text(_child(mitigation, "Description"))
        if description:
            parts.append(description)
    return "\n\n".join(parts)[:_MAX_TEXT]


def parse_cwe_catalog(text: str) -> list[dict]:
    """Parse a CWE catalog XML document into a list of weakness dicts. Rejects unsafe XML."""
    try:
        root = SafeElementTree.fromstring(text)
    except (ParseError, DefusedXmlException, ValueError) as exc:
        raise CweError(f"The file is not safe, valid CWE XML: {exc}") from exc
    weaknesses_block = _child(root, "Weaknesses")
    if weaknesses_block is None:
        raise CweError("No <Weaknesses> section was found. Provide the CWE catalog XML (cwec_*.xml).")
    records = []
    for weakness in _children(weaknesses_block, "Weakness"):
        cwe_id = normalize_cwe_id(weakness.get("ID"))
        name = weakness.get("Name")
        if cwe_id is None or not name:
            continue
        description = _clean(_child(weakness, "Description").text if _child(weakness, "Description") is not None else "")
        extended = _structured_text(_child(weakness, "Extended_Description"))
        records.append({
            "cwe_id": cwe_id,
            "name": name,
            "abstraction": weakness.get("Abstraction"),
            "description": _clean(f"{description} {extended}".strip())[:_MAX_TEXT],
            "recommended_test": _detection_text(weakness),
            "mitigation": _mitigation_text(weakness),
        })
        if len(records) >= MAX_WEAKNESSES:
            break
    return records


def import_cwe_catalog(records: list[dict], actor: User | None = None) -> CweImportSummary:
    """Upsert CWE reference entries from parsed catalog records. The caller commits via this call."""
    summary = CweImportSummary()
    existing = {row.cwe_id: row for row in db.session.scalars(db.select(CweEntry))}
    for record in records:
        cwe_id = record.get("cwe_id")
        if not cwe_id or not record.get("name"):
            summary.skipped += 1
            continue
        is_new = _upsert_entry(
            existing, cwe_id, "imported", name=record["name"], abstraction=record.get("abstraction"),
            description=record.get("description", ""),
            recommended_test=record.get("recommended_test", ""), mitigation=record.get("mitigation", ""),
        )
        summary.created += int(is_new)
        summary.updated += int(not is_new)
    db.session.flush()
    audit.record(
        "cwe.imported", object_type="cwe_reference",
        details={"created": summary.created, "updated": summary.updated}, actor=actor,
    )
    db.session.commit()
    return summary


def load_cwe_file(path) -> list[dict]:
    """Read and parse a CWE catalog XML file."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CweError(f"Cannot read {path}: {exc}") from exc
    return parse_cwe_catalog(text)
