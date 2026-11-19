"""Application crawler and API discovery modules."""
from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO
from urllib.parse import parse_qsl, urlsplit
from urllib.robotparser import RobotFileParser

from flask import current_app

from app.extensions import db
from app.mapping import classify, extract
from app.mapping.client import USER_AGENT, FetchError, FetchResponse, fetch
from app.models import (
    Endpoint,
    EndpointLink,
    EndpointParameter,
    ToolRun,
    WebCookie,
    WebForm,
)
from app.recon import inventory
from app.recon.modules import JobCancelled, ReconContext, ReconModule
from app.services import engagements as engagement_service
from app.services import settings
from app.services.scope import ScopeError, parse_target

logger = logging.getLogger("ptp.mapping")

_MAX_VARIANTS_PER_PATH = 3
_MAX_OUT_OF_SCOPE = 500
_MAX_RECORDED_ENDPOINTS = 20000
_PRECONDITION_INTERVAL = 20
_MAX_OPTIONS_REQUESTS = 50
_HTML_TYPES = ("text/html", "application/xhtml+xml")
API_DEFINITION_PATHS = (
    "/openapi.json", "/swagger.json", "/api/openapi.json", "/api/swagger.json", "/v2/api-docs",
    "/v3/api-docs", "/api-docs", "/api/docs", "/swagger/v1/swagger.json", "/.well-known/openapi.json",
)
API_ROOT_PATHS = ("/api", "/api/v1", "/api/v2", "/graphql", "/rest")


@dataclass
class _QueueItem:
    url: str
    depth: int


def _bounded_int(value, key: str) -> int:
    definition = settings.DEFINITIONS[key]
    try:
        number = int(value)
    except (TypeError, ValueError):
        return settings.get_int(key)
    return max(definition.minimum, min(number, definition.maximum))


class MappingSession:
    """Shared request handling: every request is scope checked, pinned, rate limited and logged."""

    def __init__(self, ctx: ReconContext, tool_name: str):
        self.ctx = ctx
        options = (ctx.job.plan or {}).get("options") or {}
        self.max_depth = _bounded_int(options.get("max_depth"), "mapping.max_depth")
        self.max_requests = _bounded_int(options.get("max_pages"), "mapping.max_pages")
        self.respect_robots = options.get("respect_robots", True) is not False
        self.requests_sent = 0
        self.out_of_scope = 0
        self.recorded = 0
        self.stop_reason: str | None = None
        self._pins: dict[str, str | None] = {}
        self._robots: dict[str, RobotFileParser | None] = {}
        self.robots_text: dict[str, str] = {}
        self._next_slot = 0.0
        self._interval = 1.0 / max(1, ctx.rate)
        self.run = ToolRun(
            job_id=ctx.job.id, tool_name=tool_name, module=ctx.module.name,
            target=inventory.clean(ctx.engagement.primary_target_url, 2048),
            arguments=[f"max_depth={self.max_depth}", f"max_requests={self.max_requests}",
                       f"respect_robots={self.respect_robots}", f"rate={ctx.rate}/s"],
        )
        db.session.add(self.run)
        db.session.commit()
        self.workdir = Path(current_app.config["JOB_DIR"]) / str(ctx.job.id) / f"{self.run.id}-{tool_name}"
        self.workdir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.log_path = self.workdir / "requests.jsonl"
        self._log: TextIO = self.log_path.open("w")
        self._started = time.monotonic()

    def finish(self, status: str) -> None:
        self._log.close()
        data = self.log_path.read_bytes()
        self.run.status = status
        self.run.exit_code = 0 if status == "completed" else None
        self.run.duration_ms = int((time.monotonic() - self._started) * 1000)
        self.run.output_path = str(self.log_path)
        self.run.output_sha256 = hashlib.sha256(data).hexdigest()
        self.run.output_bytes = len(data)
        db.session.commit()

    def checkpoint(self) -> bool:
        """Honor pause and cancel, and stop if testing is no longer authorized."""
        self.ctx.pause_hook()
        if self.ctx.should_cancel():
            raise JobCancelled
        if self.requests_sent % _PRECONDITION_INTERVAL == 0:
            db.session.expire(self.ctx.engagement)
            failure = engagement_service.execution_precondition_failure(
                self.ctx.engagement, self.ctx.actor, self.ctx.module.method
            )
            if failure:
                self.stop_reason = failure
                self.ctx.log(f"Stopped early: {failure}", "warning")
                return False
        return self.requests_sent < self.max_requests

    def in_scope(self, url: str) -> bool:
        return self.ctx.evaluator.evaluate(url).allowed

    def pin(self, url: str) -> str | None:
        """Pass a host through the execution gate once, and remember the validated address."""
        host = urlsplit(url).hostname or ""
        if host not in self._pins:
            decision = self.ctx.gate(url)
            if decision is None:
                self._pins[host] = None
            else:
                parsed = parse_target(url)
                self._pins[host] = str(parsed.ip) if parsed.ip else decision.resolved_ips[0]
        return self._pins[host]

    def request(self, url: str, method: str = "GET") -> FetchResponse | None:
        """Send one request after every safety check. Returns ``None`` if it was not sent."""
        if not self.in_scope(url) or classify.is_unsafe_url(url):
            return None
        address = self.pin(url)
        if address is None:
            return None
        delay = self._next_slot - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        self._next_slot = time.monotonic() + self._interval
        self.requests_sent += 1
        entry = {"time": time.time(), "method": method, "url": inventory.redact_url(url), "address": address}
        try:
            response = fetch(url, address, method)
        except FetchError as exc:
            self._log.write(json.dumps({**entry, "error": str(exc)}) + "\n")
            self._log.flush()
            return None
        self._log.write(
            json.dumps({**entry, "status": response.status, "bytes": len(response.body),
                        "ms": response.elapsed_ms}) + "\n"
        )
        self._log.flush()
        return response

    def robots_for(self, url: str) -> RobotFileParser | None:
        """Load an origin's robots.txt once, recording what it lists."""
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        if origin in self._robots:
            return self._robots[origin]
        self._robots[origin] = None
        response = self.request(f"{origin}/robots.txt")
        if response is None or response.status != 200 or "html" in response.content_type:
            return None
        parser = RobotFileParser()
        parser.parse(response.text.splitlines()[:2000])
        parser.modified()  # Without this, a file with no rules would be read as "deny everything".
        self._robots[origin] = parser
        self.robots_text[origin] = response.text
        return parser

    def robots_allow(self, url: str) -> bool:
        if not self.respect_robots:
            return True
        parser = self.robots_for(url)
        return parser is None or parser.can_fetch(USER_AGENT, url)

    def save(self, url: str, *, method: str = "GET", state: str | None = None, depth: int | None = None,
             response: FetchResponse | None = None, source: str = "crawler") -> Endpoint | None:
        """Create or update an endpoint in the application map."""
        row = inventory.save_endpoint(
            self.ctx.engagement.id, self.ctx.evaluator, url, source, method=method,
            status_code=response.status if response else None,
            content_type=response.content_type if response else None,
            redirect_location=response.header("Location") if response else None,
        )
        if row is None:
            return None
        if state and (row.crawl_state != "fetched" or state == "fetched"):
            row.crawl_state = state
        if depth is not None:
            row.depth = depth if row.depth is None else min(row.depth, depth)
        row.category = row.category or classify.categorize(row.url, row.content_type or "")
        for name in extract.query_parameter_names(row.url):
            self.save_parameter(row, name, "query", source=source)
        return row

    def save_parameter(self, endpoint: Endpoint, name: str, location: str, *, data_type: str = "",
                       required: bool = False, source: str = "crawler") -> None:
        name = inventory.clean(name, 128)
        if not name:
            return
        row = db.session.scalar(
            db.select(EndpointParameter).filter_by(endpoint_id=endpoint.id, name=name, location=location)
        )
        if row is None:
            row = EndpointParameter(
                engagement_id=self.ctx.engagement.id, endpoint_id=endpoint.id, name=name,
                location=location, source=source,
            )
            db.session.add(row)
        row.data_type = inventory.clean(data_type, 32) or row.data_type
        row.required = row.required or required
        db.session.flush()

    def link(self, source: Endpoint, target: Endpoint, link_type: str) -> None:
        if source.id == target.id:
            return
        exists = db.session.scalar(
            db.select(EndpointLink.id).filter_by(source_id=source.id, target_id=target.id, link_type=link_type)
        )
        if exists is None:
            db.session.add(
                EndpointLink(
                    engagement_id=self.ctx.engagement.id, source_id=source.id, target_id=target.id,
                    link_type=link_type,
                )
            )
            db.session.flush()


def _save_cookies(session: MappingSession, endpoint: Endpoint, url: str, response: FetchResponse) -> None:
    host = (urlsplit(url).hostname or "")[:255]
    for header in response.header_values("Set-Cookie")[:50]:
        cookie = extract.parse_set_cookie(header)
        if cookie is None:
            continue
        name = inventory.clean(cookie.name, 128)
        row = db.session.scalar(
            db.select(WebCookie).filter_by(
                engagement_id=session.ctx.engagement.id, host=host, name=name, path=cookie.path
            )
        )
        if row is None:
            row = WebCookie(engagement_id=session.ctx.engagement.id, host=host, name=name, path=cookie.path)
            db.session.add(row)
        row.endpoint_id = endpoint.id
        row.domain = inventory.clean(cookie.domain, 255)
        row.secure, row.http_only = cookie.secure, cookie.http_only
        row.same_site = inventory.clean(cookie.same_site, 16)
        row.persistent = cookie.persistent
        db.session.flush()


def _save_form(session: MappingSession, page: Endpoint, form: extract.FormData) -> None:
    action = session.save(form.action, method=form.method, state="not_requested")
    if action is None:
        return
    session.link(page, action, "form")
    fields = [
        {"name": inventory.clean(item.name, 128), "type": item.field_type, "required": item.required}
        for item in form.fields
    ]
    location = "query" if form.method == "GET" else "form"
    for item in form.fields:
        session.save_parameter(action, item.name, location, data_type=item.field_type, required=item.required)
    fingerprint = hashlib.sha256(
        json.dumps([form.method, sorted(item["name"] for item in fields)]).encode()
    ).hexdigest()
    exists = db.session.scalar(
        db.select(WebForm.id).filter_by(page_id=page.id, action_id=action.id, fields_fingerprint=fingerprint)
    )
    if exists is None:
        db.session.add(
            WebForm(
                engagement_id=session.ctx.engagement.id, page_id=page.id, action_id=action.id,
                method=form.method, enctype=inventory.clean(form.enctype, 64), purpose=form.purpose,
                fields=fields, fields_fingerprint=fingerprint, has_password=form.has_password,
                has_file_upload=form.has_file_upload, has_csrf_token=form.has_csrf_token,
            )
        )
        db.session.flush()
    if form.has_password:
        page.category = "authentication"
    if form.has_file_upload:
        action.category = "file_upload"


class Crawler:
    """Breadth-first crawl that only ever reads pages and never submits anything."""

    def __init__(self, session: MappingSession):
        self.session = session
        self.queue: deque[_QueueItem] = deque()
        self.seen: set[str] = set()
        self.variants: Counter = Counter()

    def _pattern(self, url: str) -> tuple:
        parts = urlsplit(url)
        names = sorted({name for name, _ in parse_qsl(parts.query, keep_blank_values=True)})
        return parts.scheme, parts.netloc, parts.path, tuple(names)

    def discover(self, source: Endpoint | None, url: str, depth: int, link_type: str, method: str = "GET") -> None:
        """Record a discovered URL and decide whether it may be requested."""
        session = self.session
        url = inventory.canonical_url(url)
        session.recorded += 1
        if session.recorded == _MAX_RECORDED_ENDPOINTS:
            session.ctx.log("Reached the endpoint recording limit for this crawl.", "warning")
        if session.recorded >= _MAX_RECORDED_ENDPOINTS:
            return
        if not session.in_scope(url):
            if session.out_of_scope >= _MAX_OUT_OF_SCOPE:
                return
            session.out_of_scope += 1
            state = "out_of_scope"
        elif method != "GET" or "{param}" in url:
            state = "not_requested"
        elif classify.is_unsafe_url(url):
            state = "skipped_unsafe"
        elif classify.is_static_url(url):
            state = "skipped_static"
        elif not session.robots_allow(url):
            state = "skipped_robots"
        else:
            state = "not_requested"
            pattern = self._pattern(url)
            if url not in self.seen and depth <= session.max_depth and self.variants[pattern] < _MAX_VARIANTS_PER_PATH:
                self.seen.add(url)
                self.variants[pattern] += 1
                self.queue.append(_QueueItem(url, depth))
        target = session.save(url, method=method, state=state, depth=depth)
        if source is not None and target is not None:
            session.link(source, target, link_type)

    def _process_page(self, endpoint: Endpoint, item: _QueueItem, response: FetchResponse) -> None:
        page = extract.parse_page(item.url, response.text)
        endpoint.title = inventory.clean(page.title, 255) or endpoint.title
        for form in page.forms:
            _save_form(self.session, endpoint, form)
        for url, link_type in page.links.items():
            self.discover(endpoint, url, item.depth + 1, link_type)
        self._process_script(endpoint, item, page.inline_script)

    def _process_script(self, endpoint: Endpoint, item: _QueueItem, script: str) -> None:
        for url, method in extract.extract_js_routes(item.url, script).items():
            self.discover(endpoint, url, item.depth + 1, "javascript", method)

    def _process_sitemap(self, origin_url: str) -> None:
        session = self.session
        parser = session.robots_for(origin_url)
        sitemaps = list(parser.site_maps() or []) if parser else []
        parts = urlsplit(origin_url)
        for sitemap in [*sitemaps, f"{parts.scheme}://{parts.netloc}/sitemap.xml"][:3]:
            if not session.in_scope(sitemap) or not session.robots_allow(sitemap):
                continue
            response = session.request(sitemap)
            if response is not None and response.status == 200:
                for url in extract.parse_sitemap(sitemap, response.text):
                    self.discover(None, url, 1, "sitemap")

    def _record_robots_paths(self, origin_url: str) -> None:
        """List paths named by robots.txt. They are useful attack surface but are not requested."""
        session = self.session
        parts = urlsplit(origin_url)
        origin = f"{parts.scheme}://{parts.netloc}"
        session.robots_for(origin_url)
        text = session.robots_text.get(origin)
        if text is None:
            return
        for url in extract.parse_robots(f"{origin}/robots.txt", text).disallowed:
            state = "skipped_robots" if session.respect_robots else "not_requested"
            if not session.in_scope(url):
                state = "out_of_scope"
            session.save(url, state=state, source="robots")

    def run(self) -> None:
        session = self.session
        seeds = session.ctx.web_urls()
        for url in seeds:
            if session.pin(url) is None:
                continue
            self._record_robots_paths(url)
            self._process_sitemap(url)
            self.discover(None, url, 0, "link")
        db.session.commit()

        while self.queue and session.checkpoint():
            item = self.queue.popleft()
            response = session.request(item.url)
            if response is None:
                session.save(item.url, state="error", depth=item.depth)
                db.session.commit()
                continue
            endpoint = session.save(item.url, state="fetched", depth=item.depth, response=response)
            if endpoint is None:
                continue
            _save_cookies(session, endpoint, item.url, response)
            location = response.header("Location")
            endpoint.requires_auth = classify.requires_authentication(
                response.status, location, response.header("WWW-Authenticate")
            )
            endpoint.category = classify.categorize(endpoint.url, response.content_type)
            allow = response.header("Allow")
            if allow:
                endpoint.allowed_methods = inventory.clean(allow, 128)
            if location and 300 <= response.status < 400:
                target = extract.normalize_link(item.url, location)
                if target:
                    self.discover(endpoint, target, item.depth + 1, "redirect")
            elif response.status < 400 and response.content_type in _HTML_TYPES:
                self._process_page(endpoint, item, response)
            elif response.status < 400 and "javascript" in response.content_type:
                self._process_script(endpoint, item, response.text)
            db.session.commit()
        if self.queue and session.requests_sent >= session.max_requests:
            session.ctx.log(f"Stopped at the limit of {session.max_requests} requests.", "warning")


def _run_session(ctx: ReconContext, tool_name: str, body) -> MappingSession:
    session = MappingSession(ctx, tool_name)
    try:
        body(session)
    except JobCancelled:
        db.session.rollback()
        session.finish("cancelled")
        raise
    except Exception:
        db.session.rollback()
        session.finish("failed")
        raise
    session.finish("completed")
    return session


def run_app_crawl(ctx: ReconContext) -> None:
    """Crawl in-scope web applications and build the endpoint inventory."""
    session = _run_session(ctx, "crawler", lambda item: Crawler(item).run())
    total = db.session.scalar(
        db.select(db.func.count()).select_from(Endpoint).filter_by(engagement_id=ctx.engagement.id)
    )
    ctx.log(f"Crawl finished after {session.requests_sent} requests. The map holds {total} endpoints.")


def _discover_api(session: MappingSession) -> None:
    origins = {}
    for url in session.ctx.web_urls():
        parts = urlsplit(url)
        origins.setdefault(f"{parts.scheme}://{parts.netloc}", url)
    definitions = routes = 0
    for origin in origins:
        for path in API_DEFINITION_PATHS:
            url = origin + path
            if not session.checkpoint():
                return
            if not session.in_scope(url) or not session.robots_allow(url):
                continue
            response = session.request(url)
            if response is None or response.status != 200 or "json" not in response.content_type:
                continue
            operations = extract.parse_openapi(origin, response.text)
            if operations is None:
                continue
            definitions += 1
            document = session.save(url, state="fetched", response=response, source="api_discovery")
            if document is not None:
                document.category = "api"
            for operation in operations:
                target = session.save(operation.url, method=operation.method, state="not_requested", source="api_spec")
                if target is None:
                    continue
                target.category = "api"
                routes += 1
                if document is not None:
                    session.link(document, target, "api_spec")
                for name, location, data_type, required in operation.parameters:
                    session.save_parameter(target, name, location, data_type=data_type, required=required, source="api_spec")
            db.session.commit()
        for path in API_ROOT_PATHS:
            url = origin + path
            if not session.checkpoint():
                return
            if not session.in_scope(url) or not session.robots_allow(url):
                continue
            response = session.request(url)
            if response is not None and response.status != 404:
                row = session.save(url, state="fetched", response=response, source="api_discovery")
                if row is not None:
                    row.category = classify.categorize(url, response.content_type)
                    row.requires_auth = classify.requires_authentication(
                        response.status, response.header("Location"), response.header("WWW-Authenticate")
                    )
                db.session.commit()

    candidates = db.session.scalars(
        db.select(Endpoint)
        .filter_by(engagement_id=session.ctx.engagement.id, in_scope=True, method="GET", crawl_state="fetched")
        .where(Endpoint.category.in_(("api", "graphql")))
        .limit(_MAX_OPTIONS_REQUESTS)
    ).all()
    for endpoint in candidates:
        if not session.checkpoint():
            return
        response = session.request(endpoint.url, "OPTIONS")
        if response is not None and response.header("Allow"):
            endpoint.allowed_methods = inventory.clean(response.header("Allow"), 128)
            db.session.commit()
    session.ctx.log(f"{definitions} API definitions found, describing {routes} routes.")


def run_api_discovery(ctx: ReconContext) -> None:
    """Look for published API definitions and identify the methods API routes accept."""
    _run_session(ctx, "api_discovery", _discover_api)


MAPPING_MODULES = {
    module.name: module
    for module in (
        ReconModule(
            "app_crawl", "Application crawl",
            "Follow in-scope links, and record forms, parameters, cookies and redirects. Forms are never submitted.",
            "content_discovery", (), run_app_crawl,
            covers=("WSTG-INFO-06", "WSTG-INFO-07", "WSTG-SESS-02", "WSTG-SESS-05"),
        ),
        ReconModule(
            "api_discovery", "API discovery",
            "Find OpenAPI and Swagger definitions and API roots, then identify accepted methods.",
            "content_discovery", (), run_api_discovery, covers=("WSTG-APIT-01",),
        ),
    )
}

__all__ = ["MAPPING_MODULES", "API_DEFINITION_PATHS", "Crawler", "MappingSession", "ScopeError"]
