"""Map differently named scanner detections onto one vulnerability taxonomy."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class VulnerabilityClass:
    key: str
    label: str
    cwe: str
    owasp: str
    wstg: str | None
    pattern: re.Pattern
    cwes: tuple[str, ...] = ()


def _class(key, label, cwe, owasp, wstg, pattern, *others) -> VulnerabilityClass:
    return VulnerabilityClass(key, label, cwe, owasp, wstg, re.compile(pattern, re.I), (cwe, *others))


# Order matters: specific classes come before broad ones.
CLASSES = (
    _class("nosql_injection", "NoSQL injection", "CWE-943", "A03:2021 Injection", "WSTG-INPV-05", r"no-?sql.{0,12}inject"),
    _class("sql_injection", "SQL injection", "CWE-89", "A03:2021 Injection", "WSTG-INPV-05", r"\bsql.{0,4}inject|\bsqli\b"),
    _class("dom_xss", "DOM-based cross-site scripting", "CWE-79", "A03:2021 Injection", "WSTG-CLNT-01", r"dom[- ]?(based)?[- ]?(xss|cross)"),
    _class("stored_xss", "Stored cross-site scripting", "CWE-79", "A03:2021 Injection", "WSTG-INPV-02", r"(stored|persistent)[- ]?(xss|cross)"),
    _class("cross_site_scripting", "Cross-site scripting", "CWE-79", "A03:2021 Injection", "WSTG-INPV-01", r"cross[- ]?site[- ]?script|\bxss\b", "CWE-80"),
    _class("template_injection", "Server-side template injection", "CWE-1336", "A03:2021 Injection", "WSTG-INPV-18", r"template.{0,4}inject|\bssti\b", "CWE-94"),
    _class("command_injection", "OS command injection", "CWE-78", "A03:2021 Injection", "WSTG-INPV-12", r"(command|cmd|os).{0,4}inject|\brce\b|remote code exec", "CWE-77"),
    _class("ldap_injection", "LDAP injection", "CWE-90", "A03:2021 Injection", "WSTG-INPV-06", r"ldap.{0,4}inject"),
    _class("xpath_injection", "XPath injection", "CWE-643", "A03:2021 Injection", "WSTG-INPV-09", r"xpath.{0,4}inject"),
    _class("xxe", "XML external entity", "CWE-611", "A05:2021 Security Misconfiguration", "WSTG-INPV-07", r"\bxxe\b|xml external entit"),
    _class("crlf_injection", "CRLF injection", "CWE-93", "A03:2021 Injection", "WSTG-INPV-15", r"\bcrlf\b|header inject|response split", "CWE-113"),
    _class("request_smuggling", "HTTP request smuggling", "CWE-444", "A05:2021 Security Misconfiguration", "WSTG-INPV-15", r"request smuggl|desync"),
    _class("host_header_injection", "Host header injection", "CWE-644", "A03:2021 Injection", "WSTG-INPV-17", r"host header"),
    _class("ssrf", "Server-side request forgery", "CWE-918", "A10:2021 Server-Side Request Forgery", "WSTG-INPV-19", r"\bssrf\b|server[- ]?side request forg"),
    _class("file_inclusion", "File inclusion", "CWE-98", "A03:2021 Injection", "WSTG-ATHZ-01", r"\b[lr]fi\b|file inclusion"),
    _class("path_traversal", "Path traversal", "CWE-22", "A01:2021 Broken Access Control", "WSTG-ATHZ-01", r"path travers|directory travers", "CWE-23", "CWE-35"),
    _class("open_redirect", "Open redirect", "CWE-601", "A01:2021 Broken Access Control", "WSTG-CLNT-04", r"open[- ]?redirect|external redirect"),
    _class("csrf", "Cross-site request forgery", "CWE-352", "A01:2021 Broken Access Control", "WSTG-SESS-05", r"\bcsrf\b|cross[- ]?site request forg|anti-?csrf"),
    _class("cors", "CORS misconfiguration", "CWE-942", "A05:2021 Security Misconfiguration", "WSTG-CLNT-07", r"\bcors\b|cross[- ]?origin resource|cross-domain misconfig"),
    _class("clickjacking", "Clickjacking", "CWE-1021", "A05:2021 Security Misconfiguration", "WSTG-CLNT-09", r"clickjack|x-frame-options|anti-clickjacking|frame-ancestors"),
    _class("hsts", "Missing HTTP Strict Transport Security", "CWE-319", "A05:2021 Security Misconfiguration", "WSTG-CONF-07", r"\bhsts\b|strict[- ]transport"),
    _class("cookie_security", "Insecure cookie attributes", "CWE-614", "A05:2021 Security Misconfiguration", "WSTG-SESS-02", r"cookie.{0,40}(secure|httponly|samesite|flag|attribute)|(secure|httponly|samesite).{0,30}cookie", "CWE-1004", "CWE-1275"),
    _class("weak_tls", "Weak TLS configuration", "CWE-326", "A02:2021 Cryptographic Failures", "WSTG-CRYP-01", r"\b(weak|deprecated|insecure).{0,20}(tls|ssl|cipher)|\b(tls|ssl).{0,20}(weak|deprecated|version|expired)", "CWE-327"),
    _class("insecure_deserialization", "Insecure deserialization", "CWE-502", "A08:2021 Software and Data Integrity Failures", None, r"deseriali[sz]"),
    _class("unsafe_file_upload", "Unsafe file upload", "CWE-434", "A04:2021 Insecure Design", "WSTG-BUSL-09", r"file upload|unrestricted upload"),
    _class("cleartext_credentials", "Credentials sent without encryption", "CWE-523", "A02:2021 Cryptographic Failures", "WSTG-ATHN-01", r"(credential|password).{0,40}(unencrypted|cleartext|plain ?text)"),
    _class("sensitive_query_parameter", "Sensitive data in URL query", "CWE-598", "A04:2021 Insecure Design", "WSTG-SESS-04", r"sensitive.{0,30}(url|query)"),
    _class("broken_access_control", "Broken access control", "CWE-285", "A01:2021 Broken Access Control", "WSTG-ATHZ-02", r"broken access control|missing authori[sz]ation|authori[sz]ation bypass", "CWE-862", "CWE-863"),
    _class("business_logic", "Business logic flaw", "CWE-840", "A04:2021 Insecure Design", "WSTG-BUSL-01", r"business logic"),
    _class("idor", "Insecure direct object reference", "CWE-639", "A01:2021 Broken Access Control", "WSTG-ATHZ-04", r"\bidor\b|\bbola\b|direct object ref"),
    _class("default_credentials", "Default credentials", "CWE-1392", "A07:2021 Identification and Authentication Failures", "WSTG-ATHN-02", r"default[- ](login|cred|password)", "CWE-798"),
    _class("authentication_bypass", "Authentication bypass", "CWE-287", "A07:2021 Identification and Authentication Failures", "WSTG-ATHN-04", r"auth(entication)?[- ]bypass", "CWE-306"),
    _class("jwt_weakness", "JWT weakness", "CWE-347", "A02:2021 Cryptographic Failures", "WSTG-SESS-01", r"\bjwt\b|json web token"),
    _class("directory_listing", "Directory listing", "CWE-548", "A05:2021 Security Misconfiguration", "WSTG-CONF-04", r"director(y|ies) (listing|browsing)|dir[- ]listing"),
    _class("graphql_exposure", "GraphQL exposure", "CWE-200", "A05:2021 Security Misconfiguration", "WSTG-APIT-01", r"graphql"),
    _class("missing_security_headers", "Missing security headers", "CWE-693", "A05:2021 Security Misconfiguration", "WSTG-CONF-02", r"content[- ]security[- ]policy|\bcsp\b|x-content-type|security headers?|referrer-policy|permissions-policy"),
    _class("information_disclosure", "Information disclosure", "CWE-200", "A05:2021 Security Misconfiguration", "WSTG-INFO-05", r"(information|info|version|data|sensitive).{0,14}(disclos|leak|expos)|stack trace|debug", "CWE-209", "CWE-497"),
    _class("vulnerable_component", "Vulnerable component", "CWE-1104", "A06:2021 Vulnerable and Outdated Components", "WSTG-CONF-01", r"\bcve-\d{4}-\d+|outdated|vulnerable (js|library|component|version)"),
)
_BY_CWE = {cwe: item for item in CLASSES for cwe in item.cwes}
_SLUG = re.compile(r"[^a-z0-9]+")


def type_label(key: str) -> str:
    """Return the display name for a canonical vulnerability type."""
    return next((item.label for item in CLASSES if item.key == key), key.replace("_", " ").capitalize())


def classify(name: str, cwe: str | None = None) -> tuple[str, VulnerabilityClass | None]:
    """Return a canonical type key and its class, using the name first and then the CWE."""
    for item in CLASSES:
        if item.pattern.search(name or ""):
            return item.key, item
    if cwe and cwe in _BY_CWE:
        item = _BY_CWE[cwe]
        return item.key, item
    return _SLUG.sub("_", (name or "unknown").lower()).strip("_")[:96] or "unknown", None
