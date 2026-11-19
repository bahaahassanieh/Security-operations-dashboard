"""Extract links, forms, routes, cookies and API definitions from untrusted responses."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit
from xml.etree.ElementTree import ParseError  # nosec B405  Parsing uses defusedxml.

from defusedxml import ElementTree as SafeElementTree
from defusedxml.common import DefusedXmlException

MAX_LINKS = 500
MAX_FORMS = 50
MAX_FIELDS = 100
MAX_URL_LENGTH = 2048
MAX_SCRIPT_BYTES = 1024 * 1024
MAX_SPEC_OPERATIONS = 1000
HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")

_CSRF_NAME = re.compile(r"csrf|xsrf|authenticity_token|requestverificationtoken|anti.?forgery|nonce", re.I)
_SEARCH_NAME = re.compile(r"^(q|query|search|keyword|term|s)$", re.I)
_JS_ROUTE = re.compile(r"""["'`](/(?:api|rest|graphql|gql|v\d{1,2})(?:/[A-Za-z0-9_\-.~/{}$:]{0,200})?)["'`]""")
_JS_FETCH = re.compile(r"""\bfetch\(\s*["'`]([^"'`\s]{1,300})["'`](?:\s*,\s*\{[^}]{0,200}?method\s*:\s*["'](\w+)["'])?""")
_JS_AXIOS = re.compile(r"""\baxios\.(get|post|put|patch|delete)\(\s*["'`]([^"'`\s]{1,300})["'`]""")
_JS_JQUERY = re.compile(r"""\$\.(get|post)\(\s*["'`]([^"'`\s]{1,300})["'`]""")
_JS_XHR = re.compile(r"""\.open\(\s*["'](GET|POST|PUT|PATCH|DELETE)["']\s*,\s*["'`]([^"'`\s]{1,300})["'`]""", re.I)
_TEMPLATE = re.compile(r"\$\{[^}]{0,80}\}")
_META_REFRESH = re.compile(r"url\s*=\s*['\"]?([^'\";]+)", re.I)


def normalize_link(base_url: str, href: str | None) -> str | None:
    """Resolve a link to an absolute http(s) URL, discarding anything else."""
    if not href:
        return None
    href = href.strip()
    if not href or len(href) > MAX_URL_LENGTH or any(ord(char) < 0x20 for char in href):
        return None
    try:
        absolute = urljoin(base_url, href)
        parts = urlsplit(absolute)
        _ = parts.port
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    return parts._replace(fragment="").geturl()


def query_parameter_names(url: str) -> list[str]:
    """Return query parameter names only. Values can hold secrets and are discarded."""
    try:
        pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        return []
    return list(dict.fromkeys(name[:128] for name, _ in pairs if name))[:MAX_FIELDS]


@dataclass
class FormField:
    name: str
    field_type: str
    required: bool


@dataclass
class FormData:
    action: str
    method: str
    enctype: str
    fields: list[FormField] = field(default_factory=list)

    @property
    def has_password(self) -> bool:
        return any(item.field_type == "password" for item in self.fields)

    @property
    def has_file_upload(self) -> bool:
        return any(item.field_type == "file" for item in self.fields)

    @property
    def has_csrf_token(self) -> bool:
        return any(item.field_type == "hidden" and _CSRF_NAME.search(item.name) for item in self.fields)

    @property
    def purpose(self) -> str:
        names = [item.name for item in self.fields]
        if self.has_password:
            return "authentication"
        if self.has_file_upload:
            return "upload"
        if self.method == "GET" and any(_SEARCH_NAME.match(name) for name in names):
            return "search"
        return "generic"


class _PageParser(HTMLParser):
    """Collect page structure. Scripts in the page are read as text and never executed."""

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.title = ""
        self.links: dict[str, str] = {}
        self.forms: list[FormData] = []
        self.inline_scripts: list[str] = []
        self._form: FormData | None = None
        self._in_title = False
        self._in_script = False
        self._base_seen = False

    def _add(self, href: str | None, link_type: str) -> None:
        url = normalize_link(self.base_url, href)
        if url and len(self.links) < MAX_LINKS:
            self.links.setdefault(url, link_type)

    def handle_starttag(self, tag, attrs):
        attributes = {key: value for key, value in attrs}
        if tag == "base" and not self._base_seen:
            base = normalize_link(self.base_url, attributes.get("href"))
            if base:
                self.base_url = base
                self._base_seen = True
        elif tag in ("a", "area"):
            self._add(attributes.get("href"), "link")
        elif tag == "script":
            self._add(attributes.get("src"), "script")
            self._in_script = not attributes.get("src")
        elif tag in ("iframe", "frame"):
            self._add(attributes.get("src"), "frame")
        elif tag == "title":
            self._in_title = True
        elif tag == "meta" and (attributes.get("http-equiv") or "").lower() == "refresh":
            match = _META_REFRESH.search(attributes.get("content") or "")
            if match:
                self._add(match.group(1), "redirect")
        elif tag == "form" and len(self.forms) < MAX_FORMS:
            action = normalize_link(self.base_url, attributes.get("action") or self.base_url)
            method = (attributes.get("method") or "GET").upper()
            self._form = FormData(
                action or self.base_url,
                method if method in ("GET", "POST") else "GET",
                (attributes.get("enctype") or "")[:64],
            )
            self.forms.append(self._form)
        elif tag in ("input", "select", "textarea", "button") and self._form is not None:
            name = attributes.get("name")
            if name and len(self._form.fields) < MAX_FIELDS:
                kind = (attributes.get("type") or ("text" if tag == "input" else tag)).lower()
                self._form.fields.append(FormField(name[:128], kind[:24], "required" in attributes))

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None
        elif tag == "title":
            self._in_title = False
        elif tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_title and len(self.title) < 255:
            self.title += data
        elif self._in_script and sum(map(len, self.inline_scripts)) < MAX_SCRIPT_BYTES:
            self.inline_scripts.append(data)


@dataclass
class PageData:
    title: str
    links: dict[str, str]
    forms: list[FormData]
    inline_script: str


def parse_page(base_url: str, html: str) -> PageData:
    """Parse an HTML document, keeping whatever could be read if it is malformed."""
    parser = _PageParser(base_url)
    try:
        parser.feed(html)
        parser.close()
    except (ValueError, AssertionError, RecursionError):
        pass
    return PageData(
        " ".join(parser.title.split())[:255], parser.links, parser.forms, "\n".join(parser.inline_scripts)
    )


def extract_js_routes(base_url: str, script: str) -> dict[str, str]:
    """Find API routes referenced in JavaScript, returned as {url: HTTP method}."""
    script = script[:MAX_SCRIPT_BYTES]
    found: dict[str, str] = {}

    def add(raw: str, method: str) -> None:
        url = normalize_link(base_url, _TEMPLATE.sub("{param}", raw))
        if url and len(found) < MAX_LINKS:
            found.setdefault(url, method.upper())

    for match in _JS_FETCH.finditer(script):
        add(match.group(1), match.group(2) or "GET")
    for pattern in (_JS_AXIOS, _JS_JQUERY):
        for match in pattern.finditer(script):
            add(match.group(2), match.group(1))
    for match in _JS_XHR.finditer(script):
        add(match.group(2), match.group(1))
    for match in _JS_ROUTE.finditer(script):
        add(match.group(1), "GET")
    return found


@dataclass(frozen=True)
class CookieInfo:
    name: str
    path: str
    domain: str
    secure: bool
    http_only: bool
    same_site: str
    persistent: bool


def parse_set_cookie(header: str) -> CookieInfo | None:
    """Read a cookie's name and attributes. The value is dropped immediately."""
    first, *attributes = header.split(";")
    name, separator, _value = first.partition("=")
    name = name.strip()
    if not separator or not name or len(name) > 128:
        return None
    values = {}
    for item in attributes[:20]:
        key, _, value = item.partition("=")
        values[key.strip().lower()] = value.strip()
    return CookieInfo(
        name=name,
        path=values.get("path", "/")[:255] or "/",
        domain=values.get("domain", "")[:255],
        secure="secure" in values,
        http_only="httponly" in values,
        same_site=values.get("samesite", "")[:16],
        persistent="max-age" in values or "expires" in values,
    )


@dataclass
class RobotsData:
    disallowed: list[str]
    sitemaps: list[str]


def parse_robots(base_url: str, text: str) -> RobotsData:
    """List paths named in robots.txt and any sitemaps it declares."""
    disallowed, sitemaps = [], []
    for line in text.splitlines()[:2000]:
        key, _, value = line.split("#", 1)[0].partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "disallow" and value.startswith("/") and "*" not in value and "$" not in value:
            url = normalize_link(base_url, value)
            if url:
                disallowed.append(url)
        elif key == "sitemap":
            url = normalize_link(base_url, value)
            if url:
                sitemaps.append(url)
    return RobotsData(list(dict.fromkeys(disallowed))[:200], list(dict.fromkeys(sitemaps))[:5])


def parse_sitemap(base_url: str, text: str) -> list[str]:
    """Return URLs listed in a sitemap, rejecting unsafe XML."""
    try:
        root = SafeElementTree.fromstring(text)
    except (ParseError, DefusedXmlException, ValueError):
        return []
    urls = []
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] == "loc" and element.text:
            url = normalize_link(base_url, element.text)
            if url:
                urls.append(url)
        if len(urls) >= MAX_LINKS:
            break
    return urls


@dataclass
class ApiOperation:
    url: str
    method: str
    parameters: list[tuple[str, str, str, bool]]  # name, location, type, required


def _schema_properties(body) -> list[tuple[str, str, str, bool]]:
    content = body.get("content") if isinstance(body, dict) else None
    media = content.get("application/json") if isinstance(content, dict) else None
    schema = media.get("schema") if isinstance(media, dict) else None
    properties = schema.get("properties") if isinstance(schema, dict) else None
    if not isinstance(properties, dict):
        return []
    required = schema.get("required") if isinstance(schema.get("required"), list) else []
    return [
        (str(name)[:128], "json", str(item.get("type", ""))[:32] if isinstance(item, dict) else "", name in required)
        for name, item in list(properties.items())[:MAX_FIELDS]
    ]


def _spec_parameter(item) -> tuple[str, str, str, bool] | None:
    if not isinstance(item, dict) or not item.get("name"):
        return None
    location = {"query": "query", "path": "path", "header": "header", "cookie": "cookie"}.get(item.get("in"))
    if location is None:
        return None
    schema = item.get("schema") if isinstance(item.get("schema"), dict) else item
    return str(item["name"])[:128], location, str(schema.get("type", ""))[:32], item.get("required") is True


def parse_openapi(origin: str, text: str) -> list[ApiOperation] | None:
    """Read operations from an OpenAPI or Swagger JSON document. Returns None if it is not one."""
    try:
        document = json.loads(text)
    except (ValueError, RecursionError):
        return None
    if not isinstance(document, dict) or not ("openapi" in document or "swagger" in document):
        return None
    paths = document.get("paths")
    if not isinstance(paths, dict):
        return None
    base = document.get("basePath") if isinstance(document.get("basePath"), str) else ""
    servers = document.get("servers")
    if not base and isinstance(servers, list) and servers and isinstance(servers[0], dict):
        server = servers[0].get("url")
        base = urlsplit(server).path if isinstance(server, str) else ""
    operations: list[ApiOperation] = []
    for path, item in paths.items():
        if not isinstance(item, dict) or not isinstance(path, str):
            continue
        shared = item.get("parameters") if isinstance(item.get("parameters"), list) else []
        for method in HTTP_METHODS:
            operation = item.get(method)
            if not isinstance(operation, dict) or len(operations) >= MAX_SPEC_OPERATIONS:
                continue
            own = operation.get("parameters") if isinstance(operation.get("parameters"), list) else []
            parsed = [entry for entry in map(_spec_parameter, [*shared, *own]) if entry]
            url = normalize_link(origin, base.rstrip("/") + "/" + path.lstrip("/"))
            if url:
                operations.append(
                    ApiOperation(url, method.upper(), parsed + _schema_properties(operation.get("requestBody")))
                )
    return operations
