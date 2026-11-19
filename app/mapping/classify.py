"""Rule-based endpoint categorization and request safety decisions."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

STATIC_EXTENSIONS = frozenset(
    {
        "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp", "css", "map", "woff", "woff2", "ttf",
        "eot", "otf", "mp3", "mp4", "webm", "avi", "mov", "zip", "gz", "tar", "rar", "7z", "pdf", "doc",
        "docx", "xls", "xlsx", "ppt", "pptx", "exe", "dmg", "iso", "bin",
    }
)

# A GET link containing one of these words may change state, so it is recorded but never requested.
UNSAFE_WORDS = frozenset(
    {
        "logout", "logoff", "signout", "delete", "del", "remove", "destroy", "drop", "purge", "wipe",
        "erase", "truncate", "deactivate", "disable", "suspend", "terminate", "shutdown", "reboot",
        "restart", "revoke", "unsubscribe", "cancel", "approve", "reject", "pay", "payment", "purchase",
        "checkout", "buy", "order", "transfer", "withdraw", "refund", "charge", "confirm", "activate",
        "reset", "install", "uninstall", "upgrade", "rollback", "execute", "exec", "run",
    }
)
_UNSAFE_PHRASES = re.compile(r"log[-_ ]?(out|off)|sign[-_ ]?out", re.I)
_WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Za-z][a-z0-9]*")

_CATEGORY_RULES = (
    ("authentication", re.compile(r"(^|/)(login|logon|signin|sign-in|auth|oauth2?|sso|saml|mfa|2fa|otp|register|signup|sign-up|password|passwd|forgot|session|token)(/|$|\.)", re.I)),
    ("administration", re.compile(r"(^|/)(admin|administrator|manage|manager|management|console|dashboard|cpanel|wp-admin|phpmyadmin)(/|$|\.)", re.I)),
    ("graphql", re.compile(r"(^|/)(graphql|gql|graphiql)(/|$)", re.I)),
    ("api", re.compile(r"(^|/)(api|rest|rpc|soap|ws|webservice|swagger|openapi|api-docs|v\d{1,2})(/|$|\.)", re.I)),
    ("file_upload", re.compile(r"(^|/)(upload|uploads|import|attachment|attachments)(/|$|\.)", re.I)),
    ("payment", re.compile(r"(^|/)(checkout|payment|payments|billing|invoice|invoices|cart|order|orders|subscribe|subscription)(/|$|\.)", re.I)),
    ("user_account", re.compile(r"(^|/)(user|users|profile|profiles|account|accounts|settings|preferences|me)(/|$|\.)", re.I)),
    ("search", re.compile(r"(^|/)(search|find|query|lookup)(/|$|\.)", re.I)),
    ("diagnostics", re.compile(r"(^|/)(debug|trace|status|health|healthz|metrics|actuator|info|phpinfo|server-status|\.git|\.env|backup|backups|test)(/|$|\.)", re.I)),
)


def url_words(url: str) -> set[str]:
    """Split a URL's path and query into lowercase words, including camelCase parts."""
    parts = urlsplit(url)
    values = [parts.path]
    try:
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            values += [key, value[:64]]
    except ValueError:
        values.append(parts.query)
    return {word.lower() for text in values for word in _WORD.findall(text)}


def is_unsafe_url(url: str) -> bool:
    """True when requesting this URL could log out, change data or move money."""
    if _UNSAFE_PHRASES.search(url):
        return True
    return bool(url_words(url) & UNSAFE_WORDS)


def is_static_url(url: str) -> bool:
    """True for binary or styling assets that hold nothing worth fetching."""
    path = urlsplit(url).path.rsplit("/", 1)[-1]
    return "." in path and path.rsplit(".", 1)[-1].lower() in STATIC_EXTENSIONS


def categorize(url: str, content_type: str = "", has_password_field: bool = False) -> str:
    """Assign an endpoint a functional category."""
    path = urlsplit(url).path or "/"
    if has_password_field:
        return "authentication"
    for name, pattern in _CATEGORY_RULES:
        if pattern.search(path):
            return name
    if is_static_url(url) or path.endswith(".js") or "javascript" in content_type or "css" in content_type:
        return "static"
    if "json" in content_type or "xml" in content_type:
        return "api"
    return "content"


def requires_authentication(status: int, location: str = "", www_authenticate: str = "") -> bool | None:
    """Infer protection from a response. ``None`` means the response gives no indication."""
    if status == 401 or www_authenticate:
        return True
    if status == 403:
        return True
    if 300 <= status < 400 and location:
        target = urlsplit(location).path
        return True if categorize(location) == "authentication" and target else None
    return False if 200 <= status < 300 else None
