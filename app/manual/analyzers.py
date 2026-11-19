"""Offline analysis of text a tester pastes in. These functions never contact a target."""
from __future__ import annotations

import base64
import binascii
import difflib
import json
import re
import time
from dataclasses import asdict, dataclass

from app.findings.service import redact_evidence

MAX_INPUT = 64 * 1024
_MAX_DIFF_LINES = 200
_MAX_COMPARE = 20000
_MAX_COMPARE_LINES = 1500
_MAX_TOKEN_LIFETIME = 24 * 60 * 60
_SENSITIVE_CLAIM = re.compile(r"pass|pwd|secret|ssn|card|cvv|private|api[_-]?key", re.I)
_SESSION_COOKIE = re.compile(r"sess|sid|auth|token|jwt", re.I)


class AnalyzerError(ValueError):
    """The pasted text could not be analyzed."""


@dataclass(frozen=True)
class Issue:
    severity: str
    title: str
    detail: str
    reference: str = ""


def _bounded(text: str) -> str:
    text = (text or "").strip()
    if not text:
        raise AnalyzerError("Paste some text to analyze.")
    if len(text) > MAX_INPUT:
        raise AnalyzerError("Input is limited to 64 KB.")
    return text


def _decode_segment(segment: str) -> dict:
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        value = json.loads(raw.decode("utf-8"))
    except (binascii.Error, ValueError, RecursionError) as exc:
        raise AnalyzerError("This is not a readable JSON Web Token.") from exc
    if not isinstance(value, dict):
        raise AnalyzerError("This is not a readable JSON Web Token.")
    return value


def _display_claims(claims: dict) -> dict:
    return {
        str(key)[:80]: "[MASKED]" if _SENSITIVE_CLAIM.search(str(key)) else str(value)[:200]
        for key, value in list(claims.items())[:50]
    }


def analyze_jwt(token: str, now: float | None = None) -> dict:
    """Decode a token and review its design. The signature is neither verified nor altered."""
    text = re.sub(r"^bearer\s+", "", _bounded(token), flags=re.I)
    parts = text.split(".")
    if len(parts) != 3:
        raise AnalyzerError("A JSON Web Token has three parts separated by dots.")
    header, claims = _decode_segment(parts[0]), _decode_segment(parts[1])
    now = time.time() if now is None else now
    issues: list[Issue] = []
    algorithm = str(header.get("alg", ""))
    if algorithm.lower() == "none" or not parts[2]:
        issues.append(Issue("critical", "Token is unsigned", "The token declares no signature. Confirm that the server rejects unsigned tokens.", "WSTG-SESS-01"))
    elif algorithm.upper().startswith("HS"):
        issues.append(Issue("info", "Shared-secret signature", f"{algorithm} depends on a long, random secret kept only on the server.", "WSTG-CRYP-04"))
    for name in ("jku", "x5u", "jwk"):
        if name in header:
            issues.append(Issue("medium", f"Header carries a {name} key source", "Confirm that the server ignores untrusted key locations.", "WSTG-SESS-01"))
    expiry = claims.get("exp")
    if not isinstance(expiry, (int, float)) or isinstance(expiry, bool):
        issues.append(Issue("high", "No expiry", "The token has no valid exp claim, so it may never expire.", "WSTG-SESS-07"))
    else:
        if expiry < now:
            issues.append(Issue("info", "Token has expired", "Confirm that the server rejects this token.", "WSTG-SESS-07"))
        issued = claims.get("iat") if isinstance(claims.get("iat"), (int, float)) else now
        if expiry - issued > _MAX_TOKEN_LIFETIME:
            hours = int((expiry - issued) / 3600)
            issues.append(Issue("medium", "Long token lifetime", f"The token is valid for about {hours} hours.", "WSTG-SESS-07"))
    for name, label in (("iss", "issuer"), ("aud", "audience")):
        if name not in claims:
            issues.append(Issue("low", f"No {label} claim", f"Without {name}, tokens may be accepted by the wrong service.", "WSTG-SESS-01"))
    sensitive = [str(key) for key in claims if _SENSITIVE_CLAIM.search(str(key))]
    if sensitive:
        issues.append(Issue("high", "Sensitive data in token", f"Token contents are readable by anyone holding it: {', '.join(sensitive[:10])}.", "WSTG-CRYP-03"))
    return {
        "header": _display_claims(header),
        "claims": _display_claims(claims),
        "signature": f"{len(parts[2])} characters, not verified",
        "issues": [asdict(item) for item in issues],
    }


def parse_headers(text: str) -> tuple[str, list[tuple[str, str]]]:
    """Split pasted response headers into a status line and name/value pairs."""
    status, pairs = "", []
    for line in text.replace("\r\n", "\n").split("\n\n", 1)[0].split("\n"):
        if line.upper().startswith("HTTP/"):
            status = line.strip()[:120]
            continue
        name, separator, value = line.partition(":")
        if separator and name.strip():
            pairs.append((name.strip().lower(), value.strip()))
    return status, pairs


def _review_cookie(value: str) -> list[Issue]:
    name = value.split("=", 1)[0].strip()[:80]
    if not _SESSION_COOKIE.search(name):
        return []
    attributes = {item.split("=", 1)[0].strip().lower() for item in value.split(";")[1:]}
    missing = [label for key, label in (("secure", "Secure"), ("httponly", "HttpOnly"), ("samesite", "SameSite")) if key not in attributes]
    if not missing:
        return []
    return [Issue("medium", f"Cookie {name} is missing attributes", f"Missing: {', '.join(missing)}.", "WSTG-SESS-02")]


def _review_csp(policy: str) -> list[Issue]:
    issues = []
    lowered = policy.lower()
    if "'unsafe-inline'" in lowered:
        issues.append(Issue("medium", "CSP allows inline script or style", "'unsafe-inline' weakens protection against script injection.", "WSTG-CLNT-02"))
    if "'unsafe-eval'" in lowered:
        issues.append(Issue("medium", "CSP allows eval", "'unsafe-eval' lets strings run as code.", "WSTG-CLNT-02"))
    if re.search(r"(^|;)\s*(default-src|script-src)[^;]*\s\*(\s|;|$)", lowered):
        issues.append(Issue("high", "CSP allows scripts from any origin", "A wildcard source removes most of the policy's protection.", "WSTG-CLNT-02"))
    return issues


def analyze_headers(text: str) -> dict:
    """Review pasted HTTP response headers against common hardening guidance."""
    status, pairs = parse_headers(_bounded(text))
    if not pairs:
        raise AnalyzerError("No response headers were found.")
    values: dict[str, list[str]] = {}
    for name, value in pairs:
        values.setdefault(name, []).append(value)
    first = lambda name: values.get(name, [""])[0]  # noqa: E731
    issues: list[Issue] = []
    hsts = first("strict-transport-security")
    if not hsts:
        issues.append(Issue("medium", "HSTS is missing", "Browsers are not told to require HTTPS.", "WSTG-CONF-07"))
    else:
        match = re.search(r"max-age=(\d+)", hsts, re.I)
        if not match or int(match.group(1)) < 15552000:
            issues.append(Issue("low", "HSTS lifetime is short", "Use a max-age of at least 180 days.", "WSTG-CONF-07"))
    policy = first("content-security-policy")
    if not policy:
        issues.append(Issue("medium", "Content Security Policy is missing", "A CSP limits the impact of script injection.", "WSTG-CLNT-02"))
    else:
        issues.extend(_review_csp(policy))
    if not first("x-frame-options") and "frame-ancestors" not in policy.lower():
        issues.append(Issue("medium", "Framing is not restricted", "Set CSP frame-ancestors or X-Frame-Options.", "WSTG-CLNT-09"))
    if first("x-content-type-options").lower() != "nosniff":
        issues.append(Issue("low", "X-Content-Type-Options is missing", "Set the value to nosniff.", "WSTG-CONF-02"))
    if not first("referrer-policy"):
        issues.append(Issue("low", "Referrer-Policy is missing", "URLs may leak to other sites.", "WSTG-INFO-05"))
    origin = first("access-control-allow-origin")
    if origin == "*" and first("access-control-allow-credentials").lower() == "true":
        issues.append(Issue("high", "Unsafe CORS combination", "A wildcard origin is combined with credentials.", "WSTG-CLNT-07"))
    elif origin == "*":
        issues.append(Issue("low", "CORS allows any origin", "Confirm that this response holds only public data.", "WSTG-CLNT-07"))
    for name in ("server", "x-powered-by", "x-aspnet-version"):
        if re.search(r"\d", first(name)):
            issues.append(Issue("info", f"{name} reveals a version", first(name)[:120], "WSTG-INFO-02"))
    for cookie in values.get("set-cookie", [])[:30]:
        issues.extend(_review_cookie(cookie))
    return {"status": status, "header_count": len(pairs), "issues": [asdict(item) for item in issues]}


def _split_message(text: str) -> tuple[str, list[tuple[str, str]], str]:
    normalized = text.replace("\r\n", "\n")
    head, _, body = normalized.partition("\n\n")
    if head.upper().startswith("HTTP/"):
        status, pairs = parse_headers(head)
        return status, pairs, body
    return "", [], normalized


def compare_responses(first: str, second: str) -> dict:
    """Compare two captured responses, such as one resource viewed by two test accounts."""
    left, right = redact_evidence(_bounded(first)), redact_evidence(_bounded(second))
    status_a, headers_a, body_a = _split_message(left)
    status_b, headers_b, body_b = _split_message(right)
    names_a, names_b = dict(headers_a), dict(headers_b)
    ignored = {"date", "set-cookie", "etag", "content-length", "x-request-id", "age", "expires"}
    changed = sorted(
        name for name in set(names_a) | set(names_b)
        if name not in ignored and names_a.get(name) != names_b.get(name)
    )
    similarity = difflib.SequenceMatcher(None, body_a[:_MAX_COMPARE], body_b[:_MAX_COMPARE], autojunk=False).quick_ratio()
    percent = round(similarity * 100)
    diff = list(
        difflib.unified_diff(
            body_a[:_MAX_COMPARE].splitlines()[:_MAX_COMPARE_LINES], body_b[:_MAX_COMPARE].splitlines()[:_MAX_COMPARE_LINES],
            "Response A", "Response B", lineterm="", n=1,
        )
    )
    same_status = status_a == status_b
    if same_status and percent >= 95:
        indicator = "The responses are nearly identical. If only one account should have access, investigate further."
    elif not same_status:
        indicator = "The responses have different status lines, which suggests that access differs between them."
    else:
        indicator = "The response bodies differ. Review the differences below."
    return {
        "status_a": status_a, "status_b": status_b, "same_status": same_status, "similarity": percent,
        "changed_headers": changed[:50], "diff": [line[:300] for line in diff[:_MAX_DIFF_LINES]],
        "truncated": len(diff) > _MAX_DIFF_LINES, "indicator": indicator,
    }
