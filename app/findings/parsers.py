"""Normalize uploaded scanner reports. Every file is treated as hostile input."""
from __future__ import annotations

import base64
import binascii
import csv
import io
import json
import re
from dataclasses import dataclass, field
from xml.etree.ElementTree import Element, ParseError  # nosec B405  Parsing uses defusedxml.

from defusedxml import ElementTree as SafeElementTree
from defusedxml.common import DefusedXmlException

MAX_RECORDS = 5000
MAX_TEXT = 20000
MAX_EVIDENCE = 64 * 1024
FORMATS = {
    "nuclei": "Nuclei (JSONL or JSON)",
    "zap": "OWASP ZAP (JSON report)",
    "burp": "Burp Suite (XML issues)",
    "sqlmap": "sqlmap (results CSV)",
    "generic": "Sentinel generic JSON (any engine)",
}
_SEVERITIES = {
    "critical": "critical", "crit": "critical", "high": "high", "medium": "medium", "moderate": "medium",
    "med": "medium", "low": "low", "info": "info", "informational": "info", "information": "info",
    "unknown": "info", "none": "info", "note": "info",
}
_ZAP_RISK = {"0": "info", "1": "low", "2": "medium", "3": "high"}
_TAG = re.compile(r"<[^>]{0,500}>")
_CWE = re.compile(r"(?:cwe[-_ ]?)?(\d{1,5})", re.I)
_CVSS_VECTOR = re.compile(r"^CVSS:[34]\.[01]/[A-Za-z]{1,3}:[A-Za-z](?:/[A-Za-z]{1,3}:[A-Za-z])*$")
_BURP_PARAMETER = re.compile(r"\[([^\]]{1,128}?) (?:\w+ )?parameter\]", re.I)


class ReportError(ValueError):
    """The file could not be read as a supported report."""


@dataclass
class NormalizedFinding:
    name: str
    severity: str
    url: str
    source: str
    method: str = ""
    parameter: str = ""
    description: str = ""
    remediation: str = ""
    cwe: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    references: list[str] = field(default_factory=list)
    evidence: str = ""
    confidence: str = ""


@dataclass
class ParsedReport:
    file_format: str
    findings: list[NormalizedFinding]
    rejected: int = 0


def _text(value, limit: int = MAX_TEXT) -> str:
    if value is None or isinstance(value, (dict, list, bool)):
        return ""
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", str(value)).strip()[:limit]


def _plain(value, limit: int = MAX_TEXT) -> str:
    """Remove markup from report prose. The result is still escaped wherever it is displayed."""
    return re.sub(r"[ \t]+", " ", _TAG.sub(" ", _text(value, limit * 2))).strip()[:limit]


def severity(value) -> str:
    return _SEVERITIES.get(_text(value, 32).lower(), "info")


def cwe_id(value) -> str | None:
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    match = _CWE.fullmatch(_text(value, 16))
    return f"CWE-{int(match.group(1))}" if match and int(match.group(1)) > 0 else None


def cvss_score(value) -> float | None:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    return score if 0 <= score <= 10 else None


def cvss_vector(value) -> str | None:
    text = _text(value, 255)
    return text if _CVSS_VECTOR.match(text) else None


def _strings(value, limit: int = 20) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    return [_text(item, 500) for item in value[:limit] if isinstance(item, str) and item.strip()]


def _complete(item: NormalizedFinding) -> NormalizedFinding | None:
    """Accept a record only if it names both a vulnerability and an affected location."""
    item.name, item.url = _text(item.name, 255), _text(item.url, 2048)
    item.method = re.sub(r"[^A-Z]", "", _text(item.method, 10).upper())
    item.parameter = _text(item.parameter, 255)
    item.evidence = item.evidence[:MAX_EVIDENCE]
    return item if item.name and item.url else None


def _collect(file_format: str, items) -> ParsedReport:
    findings, rejected = [], 0
    for item in items:
        complete = _complete(item) if item is not None else None
        if complete is None:
            rejected += 1
        else:
            findings.append(complete)
        if len(findings) + rejected > MAX_RECORDS:
            raise ReportError(f"The file has more than {MAX_RECORDS} records. Split it and upload the parts.")
    return ParsedReport(file_format, findings, rejected)


def _load_json(text: str):
    try:
        return json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise ReportError("The file is not valid JSON.") from exc


def _nuclei_records(text: str) -> list:
    stripped = text.lstrip()
    if stripped.startswith("["):
        document = _load_json(text)
        return document if isinstance(document, list) else []
    records = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except (ValueError, RecursionError):
            records.append(None)
    return records


def _parse_nuclei(text: str):
    for record in _nuclei_records(text):
        if not isinstance(record, dict):
            yield None
            continue
        info = record.get("info") if isinstance(record.get("info"), dict) else {}
        classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
        request = _text(record.get("request"), MAX_EVIDENCE // 2)
        response = _text(record.get("response"), MAX_EVIDENCE // 2)
        extracted = "\n".join(_strings(record.get("extracted-results")))
        method = request.split(" ", 1)[0] if request else ""
        yield NormalizedFinding(
            name=_text(info.get("name")) or _text(record.get("template-id")),
            severity=severity(info.get("severity")),
            url=_text(record.get("matched-at")) or _text(record.get("url")) or _text(record.get("host")),
            source="nuclei",
            method=method,
            parameter=_text(record.get("fuzzing_parameter"), 255),
            description=_plain(info.get("description")),
            remediation=_plain(info.get("remediation")),
            cwe=cwe_id(classification.get("cwe-id")),
            cvss_score=cvss_score(classification.get("cvss-score")),
            cvss_vector=cvss_vector(classification.get("cvss-metrics")),
            references=_strings(info.get("reference")),
            evidence="\n\n".join(part for part in (extracted, request, response) if part),
            confidence=_text(record.get("template-id"), 32),
        )


def _parse_zap(text: str):
    document = _load_json(text)
    sites = document.get("site") if isinstance(document, dict) else None
    if not isinstance(sites, list):
        raise ReportError("The file is not a ZAP JSON report.")
    for site in sites:
        alerts = site.get("alerts") if isinstance(site, dict) else None
        for alert in alerts if isinstance(alerts, list) else []:
            if not isinstance(alert, dict):
                yield None
                continue
            if _text(alert.get("confidence")) == "0":  # ZAP itself marked this a false positive.
                yield None
                continue
            instances = alert.get("instances") if isinstance(alert.get("instances"), list) else [{}]
            for instance in instances or [{}]:
                instance = instance if isinstance(instance, dict) else {}
                yield NormalizedFinding(
                    name=_text(alert.get("alert")) or _text(alert.get("name")),
                    severity=_ZAP_RISK.get(_text(alert.get("riskcode")), "info"),
                    url=_text(instance.get("uri")) or _text(site.get("@name")),
                    source="zap",
                    method=_text(instance.get("method")),
                    parameter=_text(instance.get("param"), 255),
                    description=_plain(alert.get("desc")),
                    remediation=_plain(alert.get("solution")),
                    cwe=cwe_id(alert.get("cweid")),
                    references=_strings(_plain(alert.get("reference"), 2000).split()),
                    evidence="\n".join(
                        part for part in (_text(instance.get("evidence")), _text(instance.get("otherinfo"))) if part
                    ),
                    confidence=_text(alert.get("confidence"), 32),
                )


def _decoded(element: Element | None) -> str:
    if element is None or not element.text:
        return ""
    if element.get("base64") != "true":
        return _text(element.text, MAX_EVIDENCE // 2)
    encoded = element.text.strip()[: MAX_EVIDENCE * 2]
    try:
        return _text(base64.b64decode(encoded + "=" * (-len(encoded) % 4)).decode("utf-8", "replace"), MAX_EVIDENCE // 2)
    except (binascii.Error, ValueError):
        return ""


def _parse_burp(text: str):
    try:
        root = SafeElementTree.fromstring(text)
    except (ParseError, DefusedXmlException, ValueError) as exc:
        raise ReportError("The file is not safe, valid Burp Suite XML.") from exc
    if root.tag != "issues":
        raise ReportError("The file is not a Burp Suite issues report.")
    for issue in root.findall("issue"):
        rating = _text(issue.findtext("severity")).lower()
        if rating == "false positive":
            yield None
            continue
        host = _text(issue.findtext("host")).rstrip("/")
        path = _text(issue.findtext("path"))
        parameter = _BURP_PARAMETER.search(_text(issue.findtext("location"), 500))
        pair = issue.find("requestresponse")
        request = _decoded(pair.find("request")) if pair is not None else ""
        response = _decoded(pair.find("response")) if pair is not None else ""
        classification = _CWE.search(_text(issue.findtext("vulnerabilityClassifications"), 2000) or "")
        details = (_plain(issue.findtext("issueDetail")), _plain(issue.findtext("issueBackground")))
        yield NormalizedFinding(
            name=_text(issue.findtext("name")),
            severity=severity(rating),
            url=f"{host}{path}" if host else "",
            source="burp",
            method=request.split(" ", 1)[0] if request else "",
            parameter=parameter.group(1) if parameter else "",
            description="\n\n".join(part for part in details if part),
            remediation=_plain(issue.findtext("remediationBackground")) or _plain(issue.findtext("remediationDetail")),
            cwe=f"CWE-{int(classification.group(1))}" if classification else None,
            evidence="\n\n".join(part for part in (request, response) if part),
            confidence=_text(issue.findtext("confidence"), 32),
        )


def _parse_sqlmap(text: str):
    try:
        reader = csv.DictReader(io.StringIO(text, newline=""))
        rows = list(reader)
    except csv.Error as exc:
        raise ReportError("The file is not a valid sqlmap results CSV.") from exc
    for row in rows:
        values = {(key or "").strip().lower(): value for key, value in row.items() if isinstance(value, str)}
        place = _text(values.get("place"), 16)
        technique = _text(values.get("technique(s)"), 500)
        yield NormalizedFinding(
            name="SQL injection",
            severity="high",
            url=_text(values.get("target url")),
            source="sqlmap",
            method=place if place in ("GET", "POST", "PUT", "PATCH", "DELETE") else "",
            parameter=_text(values.get("parameter"), 255),
            description="sqlmap reported this parameter as injectable. A tester must validate this result.",
            cwe="CWE-89",
            evidence="\n".join(
                part for part in (f"Place: {place}" if place else "", f"Technique: {technique}" if technique else "",
                                  _text(values.get("note(s)"), 2000)) if part
            ),
        )


def _parse_generic(text: str):
    document = _load_json(text)
    default_source = "automated_engine"
    if isinstance(document, dict):
        default_source = _text(document.get("source"), 64) or default_source
        document = document.get("findings")
    if not isinstance(document, list):
        raise ReportError('Generic reports need a list of findings, or an object with a "findings" list.')
    for item in document:
        if not isinstance(item, dict):
            yield None
            continue
        yield NormalizedFinding(
            name=_text(item.get("name")) or _text(item.get("title")),
            severity=severity(item.get("severity")),
            url=_text(item.get("url")) or _text(item.get("endpoint")),
            source=re.sub(r"[^a-z0-9_.-]", "_", (_text(item.get("source"), 64) or default_source).lower()),
            method=_text(item.get("method")),
            parameter=_text(item.get("parameter"), 255),
            description=_plain(item.get("description")),
            remediation=_plain(item.get("remediation")),
            cwe=cwe_id(item.get("cwe")),
            cvss_score=cvss_score(item.get("cvss_score")),
            cvss_vector=cvss_vector(item.get("cvss_vector")),
            references=_strings(item.get("references")),
            evidence=_text(item.get("evidence"), MAX_EVIDENCE),
            confidence=_text(item.get("confidence"), 32),
        )


_PARSERS = {
    "nuclei": _parse_nuclei, "zap": _parse_zap, "burp": _parse_burp, "sqlmap": _parse_sqlmap,
    "generic": _parse_generic,
}


def detect_format(text: str) -> str:
    """Identify a report from its content rather than trusting its file name."""
    head = text.lstrip()[:4096]
    if head.startswith("<"):
        if re.search(r"<issues[\s>]", text[:8192]):
            return "burp"
        raise ReportError("This XML file is not a supported report.")
    first_line = head.splitlines()[0].lower() if head else ""
    if "target url" in first_line and "parameter" in first_line:
        return "sqlmap"
    if '"template-id"' in head or '"matched-at"' in head:
        return "nuclei"
    if head.startswith(("{", "[")):
        document = _load_json(text)
        if isinstance(document, dict) and isinstance(document.get("site"), list):
            return "zap"
        if isinstance(document, list) or (isinstance(document, dict) and "findings" in document):
            return "generic"
    raise ReportError("The report format was not recognized. Choose a format or use the generic template.")


def parse_report(text: str, file_format: str = "auto") -> ParsedReport:
    """Parse a report into normalized findings."""
    chosen = detect_format(text) if file_format == "auto" else file_format
    if chosen not in _PARSERS:
        raise ReportError("Unsupported report format.")
    return _collect(chosen, _PARSERS[chosen](text))
