"""Normalize tool output. All input is treated as hostile: bounded, typed and never executed."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterator
from xml.etree.ElementTree import Element, ParseError  # nosec B405  Parsing uses defusedxml.

from defusedxml import ElementTree as SafeElementTree
from defusedxml.common import DefusedXmlException

MAX_RECORDS = 5000
MAX_LINE_BYTES = 256 * 1024
MAX_DOCUMENT_BYTES = 64 * 1024 * 1024
_HOSTNAME = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9_-]{1,63}(?:\.[A-Za-z0-9_-]{1,63})+\.?$")
DNS_RECORD_TYPES = {"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"}
# WhatWeb plugins that describe the response rather than a technology.
_WHATWEB_NOISE = {
    "Country", "IP", "Title", "HTTPServer", "RedirectLocation", "UncommonHeaders", "Email",
    "Script", "Cookies", "HTML5", "Meta-Author", "MetaGenerator", "X-UA-Compatible",
    "PasswordField", "Frame", "Object", "Strict-Transport-Security", "X-Frame-Options",
    "X-XSS-Protection", "Content-Security-Policy", "HttpOnly", "Via-Proxy", "Allow",
}


def iter_lines(path: Path) -> Iterator[str]:
    """Yield at most ``MAX_RECORDS`` bounded lines."""
    try:
        with path.open(errors="replace") as handle:
            for _ in range(MAX_RECORDS):
                line = handle.readline(MAX_LINE_BYTES)
                if not line:
                    return
                if line.strip():
                    yield line.strip()
    except OSError:
        return


def iter_json_lines(path: Path) -> Iterator[dict]:
    """Yield JSON objects, skipping anything malformed."""
    for line in iter_lines(path):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            yield value


def read_json(path: Path):
    """Load one size-limited JSON document, returning ``None`` if it is unusable."""
    try:
        if path.stat().st_size > MAX_DOCUMENT_BYTES:
            return None
        return json.loads(path.read_text(errors="replace"))
    except (OSError, ValueError, RecursionError):
        return None


def _read_xml(text: str) -> Element | None:
    start = text.find("<?xml")
    if start < 0:
        return None
    try:
        return SafeElementTree.fromstring(text[start:])
    except (ParseError, DefusedXmlException, ValueError):
        return None


def _read_text(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_DOCUMENT_BYTES:
            return ""
        return path.read_text(errors="replace")
    except OSError:
        return ""


def _text(value) -> str:
    return value if isinstance(value, str) else ""


def _int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_subfinder(path: Path) -> list[str]:
    """Return hostnames from Subfinder JSONL."""
    return [_text(item.get("host")) for item in iter_json_lines(path) if item.get("host")]


def parse_names(path: Path) -> list[str]:
    """Return hostnames from plain output, ignoring status messages printed by the tool."""
    return [line for line in iter_lines(path) if _HOSTNAME.match(line)]


def parse_dig(path: Path) -> dict[str, dict[str, list[str]]]:
    """Group ``dig +noall +answer`` lines as {hostname: {record type: [values]}}."""
    records: dict[str, dict[str, list[str]]] = {}
    for line in iter_lines(path):
        if line.startswith(";"):
            continue
        parts = line.split(None, 4)
        if len(parts) != 5 or parts[2] != "IN" or parts[3] not in DNS_RECORD_TYPES:
            continue
        name = parts[0].rstrip(".").lower()
        values = records.setdefault(name, {}).setdefault(parts[3], [])
        if parts[4] not in values:
            values.append(parts[4][:512])
    return records


def split_technology(value: str) -> tuple[str, str]:
    """Split httpx's ``Name:version`` form."""
    name, _, version = value.partition(":")
    return name.strip(), version.strip()


SECURITY_HEADERS = (
    "strict_transport_security", "content_security_policy", "x_frame_options",
    "x_content_type_options", "referrer_policy", "permissions_policy",
)


def parse_httpx(path: Path) -> list[dict]:
    """Normalize httpx JSONL into web service records."""
    services = []
    for item in iter_json_lines(path):
        url = _text(item.get("url"))
        if not url or item.get("failed") is True:
            continue
        technologies = item.get("tech") if isinstance(item.get("tech"), list) else []
        header = item.get("header") if isinstance(item.get("header"), dict) else {}
        services.append(
            {
                "url": url,
                "host": _text(item.get("host")),
                "ip": _text(item.get("host_ip")),
                "port": _int(item.get("port")),
                "scheme": _text(item.get("scheme")),
                "status_code": _int(item.get("status_code")),
                "title": _text(item.get("title")),
                "server": _text(item.get("webserver")),
                "content_type": _text(item.get("content_type")),
                "content_length": _int(item.get("content_length")),
                "location": _text(item.get("location")),
                "security_headers": {name: _text(header.get(name))[:512] for name in SECURITY_HEADERS if header.get(name)},
                "technologies": [split_technology(_text(tech)) for tech in technologies[:50]],
            }
        )
    return services


def parse_whatweb(path: Path) -> list[dict]:
    """Normalize WhatWeb JSON into per-target technology lists."""
    document = read_json(path)
    if not isinstance(document, list):
        return []
    results = []
    for item in document[:MAX_RECORDS]:
        if not isinstance(item, dict) or not isinstance(item.get("plugins"), dict):
            continue
        technologies = []
        server = ""
        for name, details in item["plugins"].items():
            details = details if isinstance(details, dict) else {}
            if name == "HTTPServer":
                strings = details.get("string")
                server = _text(strings[0]) if isinstance(strings, list) and strings else ""
            if name in _WHATWEB_NOISE:
                continue
            versions = details.get("version")
            version = _text(versions[0]) if isinstance(versions, list) and versions else ""
            technologies.append((str(name), version.strip(" ,")))
        results.append(
            {
                "target": _text(item.get("target")),
                "status_code": _int(item.get("http_status")),
                "server": server,
                "technologies": technologies[:100],
            }
        )
    return results


def parse_ffuf(path: Path) -> list[dict]:
    """Return discovered paths from ffuf's JSON report."""
    document = read_json(path)
    results = document.get("results") if isinstance(document, dict) else None
    if not isinstance(results, list):
        return []
    return [
        {
            "url": _text(item.get("url")),
            "status_code": _int(item.get("status")),
            "content_type": _text(item.get("content-type")),
            "location": _text(item.get("redirectlocation")),
        }
        for item in results[:MAX_RECORDS]
        if isinstance(item, dict) and item.get("url")
    ]


def parse_katana(path: Path) -> list[dict]:
    """Return crawled endpoints from Katana JSONL."""
    endpoints = []
    for item in iter_json_lines(path):
        request = item.get("request") if isinstance(item.get("request"), dict) else {}
        response = item.get("response") if isinstance(item.get("response"), dict) else {}
        url = _text(request.get("endpoint"))
        if url:
            endpoints.append(
                {
                    "url": url,
                    "method": _text(request.get("method")).upper() or "GET",
                    "status_code": _int(response.get("status_code")),
                }
            )
    return endpoints


def parse_nmap(path: Path) -> list[dict]:
    """Return open TCP ports from Nmap XML."""
    root = _read_xml(_read_text(path))
    if root is None:
        return []
    services = []
    for host in root.findall("host"):
        address = host.find("address")
        if address is None:
            continue
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            details = service.attrib if service is not None else {}
            services.append(
                {
                    "ip": address.get("addr", ""),
                    "port": _int(port.get("portid")),
                    "protocol": port.get("protocol", "tcp"),
                    "service": details.get("name", ""),
                    "tunnel": details.get("tunnel", ""),
                    "product": details.get("product", ""),
                    "version": details.get("version", ""),
                }
            )
    return services[:MAX_RECORDS]


def parse_sslscan(path: Path) -> dict | None:
    """Return protocol support and certificate details from sslscan XML."""
    root = _read_xml(_read_text(path))
    test = root.find("ssltest") if root is not None else None
    if test is None:
        return None
    protocols = [
        f"{item.get('type', '').upper()} {item.get('version', '')}"
        for item in test.findall("protocol")
        if item.get("enabled") == "1"
    ]
    certificate = test.find("./certificates/certificate")

    def field(name: str) -> str:
        return (certificate.findtext(name) or "").strip() if certificate is not None else ""

    alt_names = [
        name.strip()[4:]
        for name in field("altnames").split(",")
        if name.strip().upper().startswith("DNS:")
    ]
    weak_ciphers = sorted(
        {
            item.get("cipher", "")
            for item in test.findall("cipher")
            if item.get("strength") in {"weak", "insecure", "null", "anonymous"}
        }
    )
    return {
        "protocols": protocols,
        "weak_ciphers": weak_ciphers[:50],
        "subject": field("subject"),
        "issuer": field("issuer"),
        "alt_names": alt_names[:200],
        "not_before": field("not-valid-before"),
        "not_after": field("not-valid-after"),
        "expired": field("expired") == "true",
        "self_signed": field("self-signed") == "true",
        "signature_algorithm": field("signature-algorithm"),
    }
