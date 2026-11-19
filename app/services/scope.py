"""Scope enforcement engine.

This module is the single authority on whether a target may be touched. It has no
Flask or database dependencies so it can be tested exhaustively and reused by
background workers.

Design rules:

* **Default deny.** A target is allowed only when an inclusion rule matches it.
* **Exclusions win** over every inclusion.
* **Canonicalize before comparing.** URL tricks (userinfo, encoded hosts, decimal or
  hex IPs, IPv4-mapped IPv6, trailing dots, unicode homographs) are normalized or rejected.
* **Fail closed.** Anything unparseable, or a failed DNS lookup at execution time, is denied.
* **Resolved addresses are checked too**, which blocks DNS rebinding of an authorized
  name onto loopback, private or excluded addresses.
"""
from __future__ import annotations

import ipaddress
import posixpath
import re
import socket
from dataclasses import dataclass, field
from typing import Callable, Iterable
from urllib.parse import unquote, urlsplit

import idna
from publicsuffixlist import PublicSuffixList

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str], list[str]]

MAX_TARGET_LENGTH = 2048
DEFAULT_MIN_IPV4_PREFIX = 16
DEFAULT_MIN_IPV6_PREFIX = 48
DEFAULT_PORTS = {"http": 80, "https": 443}

_PSL = PublicSuffixList(accept_unknown=False)
_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_NUMERIC_LABEL = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_IPV4_MAPPED = ipaddress.ip_network("::ffff:0:0/96")
_USERINFO = re.compile(r"(^|//)[^/?#]*@")
_QUERY = re.compile(r"\?.*$", re.S)

# Never testable, even if a CIDR rule covers them: cloud metadata services,
# link-local, multicast, unspecified and reserved ranges.
HARD_DENY_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "0.0.0.0/8",
        "169.254.0.0/16",
        "100.100.100.200/32",
        "168.63.129.16/32",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "fe80::/10",
        "ff00::/8",
        "fd00:ec2::254/128",
    )
)


class ScopeError(ValueError):
    """Raised when a target or scope rule is malformed or unacceptably broad."""


@dataclass(frozen=True)
class ParsedTarget:
    """A canonical view of a target string."""

    raw: str
    host: str
    ip: IPAddress | None
    scheme: str | None
    port: int | None
    path: str

    @property
    def effective_port(self) -> int | None:
        return self.port or DEFAULT_PORTS.get(self.scheme or "")


@dataclass(frozen=True)
class ScopeRule:
    """A normalized scope rule, as stored in ``engagement_scope``."""

    entry_type: str
    value: str
    is_exclusion: bool = False


@dataclass(frozen=True)
class ScopeDecision:
    """The outcome of a scope evaluation."""

    allowed: bool
    target: str
    reason: str
    host: str | None = None
    matched_rule: str | None = None
    resolved_ips: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "target": self.target,
            "host": self.host,
            "reason": self.reason,
            "matched_rule": self.matched_rule,
            "resolved_ips": list(self.resolved_ips),
        }


def sanitize_target(target: str) -> str:
    """Remove embedded credentials and query values before a target is logged."""
    text = _USERINFO.sub(r"\1[REDACTED]@", str(target)[:512])
    return _QUERY.sub("?[REDACTED]", text)


def system_resolver(host: str) -> list[str]:
    """Resolve ``host`` to every address the system would connect to."""
    results = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({result[4][0] for result in results})


def canonical_ip(address: IPAddress) -> IPAddress:
    """Unwrap IPv4 addresses embedded in IPv6 so they cannot dodge IPv4 rules."""
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return address.ipv4_mapped
        if address.sixtofour is not None:
            return address.sixtofour
        if address in _NAT64:
            return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
        value = int(address)
        if 1 < value <= 0xFFFFFFFF:  # Deprecated IPv4-compatible form (::a.b.c.d).
            return ipaddress.IPv4Address(value)
    return address


def _parse_ip_literal(host: str) -> IPAddress | None:
    """Return the IP a host literal denotes, including legacy inet_aton forms."""
    try:
        return canonical_ip(ipaddress.ip_address(host))
    except ValueError:
        pass
    last_label = host.rsplit(".", 1)[-1]
    if _NUMERIC_LABEL.match(last_label):
        try:
            # 2130706433, 0x7f.1, 0177.0.0.1 and 127.1 all reach 127.0.0.1 in many clients.
            return ipaddress.IPv4Address(socket.inet_aton(host))
        except OSError as exc:
            raise ScopeError(f"Ambiguous numeric host: {host!r}") from exc
    return None


def _normalize_hostname(host: str) -> str:
    """Lowercase, strip the root dot, apply IDNA and validate DNS syntax."""
    if host.endswith("."):
        host = host[:-1]
    if not host or len(host) > 253:
        raise ScopeError("Hostname is empty or too long.")
    if not host.isascii():
        try:
            host = idna.encode(host, uts46=True).decode("ascii")
        except idna.IDNAError as exc:
            raise ScopeError(f"Invalid internationalized hostname: {exc}") from exc
    host = host.lower()
    if not all(_HOST_LABEL.match(label) for label in host.split(".")):
        raise ScopeError(f"Invalid hostname: {host!r}")
    return host


def normalize_path(path: str) -> str:
    """Decode and collapse a URL path so encoded traversal cannot escape a prefix."""
    decoded = path or "/"
    for _ in range(5):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    else:
        raise ScopeError("Path is encoded too many times.")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in decoded):
        raise ScopeError("Path contains control characters.")
    decoded = re.sub(r";[^/]*", "", decoded.replace("\\", "/"))  # Drop path parameters.
    collapsed = posixpath.normpath("/" + decoded.lstrip("/"))
    return "/" if collapsed in ("/", "//") else collapsed


def parse_target(raw: str) -> ParsedTarget:
    """Parse a URL, hostname or IP into canonical form or raise :class:`ScopeError`."""
    if not isinstance(raw, str):
        raise ScopeError("Target must be a string.")
    text = raw.strip()
    if not text:
        raise ScopeError("Target is empty.")
    if len(text) > MAX_TARGET_LENGTH:
        raise ScopeError("Target is too long.")
    if any(char.isspace() or ord(char) < 0x20 or ord(char) == 0x7F for char in text):
        raise ScopeError("Target contains whitespace or control characters.")
    if "\\" in text:
        raise ScopeError("Target contains a backslash.")

    # A bare IPv6 literal has colons that would otherwise look like a port.
    try:
        ipaddress.IPv6Address(text)
        text = f"[{text}]"
    except ValueError:
        pass

    has_scheme = "://" in text
    try:
        parts = urlsplit(text if has_scheme else f"//{text}")
        port = parts.port
    except ValueError as exc:
        raise ScopeError(f"Malformed target: {exc}") from exc

    scheme = parts.scheme.lower() if has_scheme else None
    if has_scheme and scheme not in DEFAULT_PORTS:
        raise ScopeError(f"Unsupported scheme: {scheme!r}. Only http and https are allowed.")
    if "@" in parts.netloc:
        raise ScopeError("Targets must not contain embedded credentials.")
    if port == 0:
        raise ScopeError("Port 0 is not valid.")

    host = parts.hostname or ""
    if not host:
        raise ScopeError("Target has no host.")
    if "%" in host:
        raise ScopeError("Percent-encoded hosts and IPv6 zone identifiers are not allowed.")

    host = host.rstrip(".") if host.endswith(".") and not host.endswith("..") else host
    ip = _parse_ip_literal(host)
    if ip is None:
        # IDNA can map full-width digits onto an IP, so check again after normalizing.
        host = _normalize_hostname(host)
        ip = _parse_ip_literal(host)
    canonical_host = str(ip) if ip is not None else host
    return ParsedTarget(
        raw=raw,
        host=canonical_host,
        ip=ip,
        scheme=scheme,
        port=port,
        path=normalize_path(parts.path),
    )


def detect_entry_type(value: str) -> str:
    """Infer the rule type of a user-supplied scope line."""
    text = value.strip()
    if text.startswith("*."):
        return "wildcard"
    if "://" in text:
        return "url"
    try:
        ipaddress.ip_network(text, strict=False)
    except ValueError:
        return "domain"
    return "cidr" if "/" in text else "ip"


def normalize_rule(
    value: str,
    *,
    is_exclusion: bool = False,
    min_ipv4_prefix: int = DEFAULT_MIN_IPV4_PREFIX,
    min_ipv6_prefix: int = DEFAULT_MIN_IPV6_PREFIX,
) -> ScopeRule:
    """Validate one scope line. Over-broad inclusions are rejected; exclusions may be broad."""
    text = (value or "").strip()
    if not text:
        raise ScopeError("Scope entry is empty.")
    entry_type = detect_entry_type(text)

    if entry_type == "cidr":
        try:
            network = ipaddress.ip_network(text, strict=True)
        except ValueError as exc:
            raise ScopeError(f"Invalid CIDR {text!r}: {exc}") from exc
        if network.version == 6 and network.subnet_of(_IPV4_MAPPED):
            raise ScopeError("Write IPv4-mapped ranges in IPv4 notation.")
        minimum = min_ipv4_prefix if network.version == 4 else min_ipv6_prefix
        if not is_exclusion and network.prefixlen < minimum:
            raise ScopeError(f"CIDR {text} is too broad. The narrowest allowed is /{minimum}.")
        return ScopeRule("cidr", str(network), is_exclusion)

    if entry_type == "ip":
        return ScopeRule("ip", str(canonical_ip(ipaddress.ip_address(text))), is_exclusion)

    if entry_type == "wildcard":
        base = _normalize_hostname(text[2:])
        if "*" in base or "." not in base or _PSL.is_public(base):
            raise ScopeError(f"Wildcard {text!r} is too broad: it covers a public suffix.")
        return ScopeRule("wildcard", f"*.{base}", is_exclusion)

    parsed = parse_target(text)
    if entry_type == "url":
        if parsed.scheme is None:
            raise ScopeError(f"URL rule {text!r} needs a scheme.")
        port = f":{parsed.port}" if parsed.port else ""
        host = f"[{parsed.host}]" if parsed.ip and parsed.ip.version == 6 else parsed.host
        return ScopeRule("url", f"{parsed.scheme}://{host}{port}{parsed.path}", is_exclusion)

    if parsed.ip is not None:
        return ScopeRule("ip", parsed.host, is_exclusion)
    if parsed.port or parsed.path != "/":
        raise ScopeError(f"Domain rule {text!r} must not include a port or path. Use a full URL.")
    if _PSL.is_public(parsed.host):
        raise ScopeError(f"{parsed.host!r} is a public suffix and cannot be authorized.")
    return ScopeRule("domain", parsed.host, is_exclusion)


def _path_within(path: str, prefix: str) -> bool:
    """Match on path-segment boundaries, so /app does not match /application."""
    return prefix == "/" or path == prefix or path.startswith(prefix.rstrip("/") + "/")


class ScopeEvaluator:
    """Evaluates targets against a fixed set of scope rules."""

    def __init__(self, rules: Iterable[ScopeRule], resolver: Resolver | None = None):
        rules = list(rules)
        self._inclusions = [rule for rule in rules if not rule.is_exclusion]
        self._exclusions = [rule for rule in rules if rule.is_exclusion]
        self._resolver = resolver or system_resolver

    @staticmethod
    def _matches_ip(rule: ScopeRule, address: IPAddress) -> bool:
        if rule.entry_type == "ip":
            return address == ipaddress.ip_address(rule.value)
        if rule.entry_type == "cidr":
            network = ipaddress.ip_network(rule.value)
            return address.version == network.version and address in network
        return False

    @staticmethod
    def _matches_url(rule: ScopeRule, target: ParsedTarget) -> bool:
        base = parse_target(rule.value)
        if base.host != target.host:
            return False
        if rule.is_exclusion:  # Protect the path on every scheme, port and letter case.
            return _path_within(target.path.casefold(), base.path.casefold())
        if target.scheme is None:
            return False  # A bare host is broader than a URL rule.
        return (
            base.scheme == target.scheme
            and base.effective_port == target.effective_port
            and _path_within(target.path, base.path)
        )

    def _matches(self, rule: ScopeRule, target: ParsedTarget) -> bool:
        if rule.entry_type == "url":
            return self._matches_url(rule, target)
        if target.ip is not None:
            return self._matches_ip(rule, target.ip)
        if rule.entry_type == "domain":
            if rule.is_exclusion:  # Exclusions also protect everything beneath the name.
                return target.host == rule.value or target.host.endswith(f".{rule.value}")
            return target.host == rule.value
        if rule.entry_type == "wildcard":
            return target.host.endswith(rule.value[1:])
        return False

    @staticmethod
    def _hard_denied(address: IPAddress) -> bool:
        return any(
            address.version == network.version and address in network
            for network in HARD_DENY_NETWORKS
        )

    def _check_resolved(self, target: ParsedTarget) -> tuple[str | None, tuple[str, ...]]:
        """Return (denial reason, resolved addresses) for a hostname."""
        try:
            resolved = self._resolver(target.host)
            parsed_addresses = [
                canonical_ip(ipaddress.ip_address(text.split("%", 1)[0])) for text in resolved
            ]
        except (OSError, ValueError) as exc:
            return f"DNS resolution failed: {exc}", ()
        if not resolved:
            return "DNS resolution returned no addresses.", ()
        addresses = tuple(resolved)
        for address in parsed_addresses:
            if self._hard_denied(address):
                return f"{target.host} resolves to prohibited address {address}.", addresses
            for rule in self._exclusions:
                if self._matches_ip(rule, address):
                    return (
                        f"{target.host} resolves to {address}, excluded by {rule.value}.",
                        addresses,
                    )
            if not address.is_global and not any(
                self._matches_ip(rule, address) for rule in self._inclusions
            ):
                return (
                    f"{target.host} resolves to non-public address {address}, "
                    "which is not explicitly authorized.",
                    addresses,
                )
        return None, addresses

    def evaluate(self, target: str, *, resolve: bool = False) -> ScopeDecision:
        """Decide whether ``target`` is in scope.

        ``resolve=True`` must be used immediately before any network activity.
        """
        try:
            parsed = parse_target(target)
        except ScopeError as exc:
            return ScopeDecision(False, str(target)[:255], f"Rejected: {exc}")

        def deny(reason: str, rule: str | None = None, ips: tuple[str, ...] = ()) -> ScopeDecision:
            return ScopeDecision(False, target, reason, parsed.host, rule, ips)

        if parsed.ip is not None and self._hard_denied(parsed.ip):
            return deny(f"{parsed.ip} is a prohibited address range.")

        for rule in self._exclusions:
            if self._matches(rule, parsed):
                return deny(f"Explicitly excluded by rule {rule.value}.", rule.value)

        matched = next((rule for rule in self._inclusions if self._matches(rule, parsed)), None)
        if matched is None:
            return deny("No authorization rule matches this target.")

        resolved: tuple[str, ...] = ()
        if resolve and parsed.ip is None:
            reason, resolved = self._check_resolved(parsed)
            if reason:
                return deny(reason, matched.value, resolved)

        return ScopeDecision(
            True, target, f"Authorized by rule {matched.value}.", parsed.host, matched.value, resolved
        )
