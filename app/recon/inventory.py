"""Store discovered assets. Every item is classified against scope as it is saved."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.extensions import db
from app.models import Asset, Endpoint, Subdomain, Technology, utcnow
from app.services.scope import ScopeError, ScopeEvaluator, parse_target

_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")
_SENSITIVE_PARAMETER = re.compile(
    r"pass|pwd|secret|token|api[_-]?key|apikey|auth|session|sessid|sid$|jwt|bearer|signature|sig$|credential|otp",
    re.I,
)


def clean(value, limit: int) -> str:
    """Strip control characters and bound the length of tool-supplied text."""
    return _CONTROL.sub(" ", str(value or "")).strip()[:limit]


def canonical_url(url: str) -> str:
    """Give equivalent URLs one form, so a site is never stored or tested twice."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return url
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return url
    scheme = parts.scheme.lower()
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname.lower()
    default = {"http": 80, "https": 443}[scheme]
    netloc = host if port in (None, default) else f"{host}:{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def redact_url(url: str) -> str:
    """Mask the values of query parameters that commonly carry credentials."""
    try:
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
    except ValueError:
        return url
    if not any(_SENSITIVE_PARAMETER.search(name) for name, _ in pairs):
        return url
    masked = [(name, "REDACTED" if _SENSITIVE_PARAMETER.search(name) else value) for name, value in pairs]
    return urlunsplit(parts._replace(query=urlencode(masked)))


def _merged_sources(current: str, source: str) -> str:
    sources = {item for item in current.split(",") if item} | {source}
    return ",".join(sorted(sources))[:64]


def save_subdomain(
    engagement_id: int,
    evaluator: ScopeEvaluator,
    hostname: str,
    source: str,
    *,
    dns_records: dict | None = None,
    resolved_ips: list[str] | None = None,
) -> Subdomain | None:
    """Create or update a hostname. Invalid names are discarded."""
    try:
        parsed = parse_target(clean(hostname, 255))
    except ScopeError:
        return None
    if parsed.ip is not None or parsed.scheme is not None or parsed.port or parsed.path != "/":
        return None
    row = db.session.scalar(
        db.select(Subdomain).filter_by(engagement_id=engagement_id, hostname=parsed.host)
    )
    if row is None:
        row = Subdomain(
            engagement_id=engagement_id, hostname=parsed.host, source=source,
            dns_records={}, resolved_ips=[],
        )
        db.session.add(row)
    row.source = _merged_sources(row.source, source)
    row.in_scope = evaluator.evaluate(parsed.host).allowed
    if dns_records:
        row.dns_records = {**(row.dns_records or {}), **dns_records}
    if resolved_ips:
        row.resolved_ips = sorted(set(row.resolved_ips or []) | set(resolved_ips))
        row.is_alive = True
    db.session.flush()
    return row


def save_asset(
    engagement_id: int,
    evaluator: ScopeEvaluator,
    asset_type: str,
    value: str,
    source: str,
    *,
    port: int | None = None,
    protocol: str | None = None,
    service: str | None = None,
    ip_address: str | None = None,
    attributes: dict | None = None,
    scope_target: str | None = None,
) -> Asset:
    """Create or update an asset, keyed on type, value and port."""
    value = clean(value, 2048)
    if asset_type == "web_service":
        value = canonical_url(value)
    row = db.session.scalar(
        db.select(Asset).filter_by(
            engagement_id=engagement_id, asset_type=asset_type, value=value, port=port
        )
    )
    if row is None:
        row = Asset(
            engagement_id=engagement_id, asset_type=asset_type, value=value, port=port,
            source=source, attributes={},
        )
        db.session.add(row)
    row.source = _merged_sources(row.source, source)
    row.in_scope = evaluator.evaluate(scope_target or value).allowed
    row.last_seen = utcnow()
    row.protocol = clean(protocol, 16) or row.protocol
    row.service = clean(service, 64) or row.service
    row.ip_address = clean(ip_address, 45) or row.ip_address
    if attributes:
        row.attributes = {**(row.attributes or {}), **attributes}
    db.session.flush()
    return row


def save_endpoint(
    engagement_id: int,
    evaluator: ScopeEvaluator,
    url: str,
    source: str,
    *,
    method: str = "GET",
    status_code: int | None = None,
    content_type: str | None = None,
    redirect_location: str | None = None,
    asset_id: int | None = None,
) -> Endpoint | None:
    """Create or update an endpoint. Anything but an http(s) URL is discarded."""
    url = clean(url, 2048)
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    url = redact_url(canonical_url(url))
    parts = urlsplit(url)
    method = clean(method, 10).upper() or "GET"
    row = db.session.scalar(
        db.select(Endpoint).filter_by(engagement_id=engagement_id, method=method, url=url)
    )
    if row is None:
        row = Endpoint(
            engagement_id=engagement_id, url=url, method=method, source=source,
            path=(parts.path or "/")[:2048], parameters=[],
        )
        db.session.add(row)
    row.source = _merged_sources(row.source, source)
    row.in_scope = evaluator.evaluate(url).allowed
    row.status_code = status_code if status_code is not None else row.status_code
    row.content_type = clean(content_type, 128) or row.content_type
    row.redirect_location = redact_url(clean(redirect_location, 2048)) or row.redirect_location
    row.asset_id = asset_id or row.asset_id
    db.session.flush()
    return row


def save_technology(
    engagement_id: int, asset_id: int, name: str, version: str, source: str, confidence: int = 70
) -> Technology | None:
    """Record a fingerprinted technology on an asset."""
    name, version = clean(name, 128), clean(version, 64)
    if not name:
        return None
    row = db.session.scalar(
        db.select(Technology).filter_by(
            engagement_id=engagement_id, asset_id=asset_id, name=name, version=version
        )
    )
    if row is None:
        row = Technology(
            engagement_id=engagement_id, asset_id=asset_id, name=name, version=version,
            source=source, confidence=confidence,
        )
        db.session.add(row)
    row.source = _merged_sources(row.source, source)
    row.confidence = max(row.confidence, confidence)
    db.session.flush()
    return row
