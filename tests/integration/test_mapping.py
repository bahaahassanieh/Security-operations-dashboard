"""Application mapping, tested with the real crawler against real loopback HTTP servers."""
from __future__ import annotations

import gzip
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app.extensions import db
from app.mapping import classify, client, extract
from app.models import (
    ActivityLog,
    Endpoint,
    EndpointLink,
    EndpointParameter,
    ExecutionJob,
    ToolRun,
    WebCookie,
    WebForm,
)
from app.services import engagements as service
from app.services import jobs
from tests.conftest import engagement_data

COOKIE_SECRET = "SESSIONVALUE-must-never-be-stored"
QUERY_SECRET = "querysecret123"


def home_page(trap_port: int) -> str:
    return f"""<html><head><title>Lab Home</title><script src="/app.js"></script>
    <script>fetch("/api/inline", {{method: "POST"}});</script></head><body>
    <a href="/about">About</a> <a href="/login">Login</a> <a href="/logout">Log out</a>
    <a href="/account/delete?id=5">Delete account</a> <a href="/private/secret">Private</a>
    <a href="/hidden/page">Hidden</a> <a href="http://127.0.0.2:{trap_port}/trap">Elsewhere</a>
    <a href="/go">Redirect away</a> <a href="/admin">Admin</a> <a href="/secure">Secure</a>
    <a href="/forbidden">Forbidden</a> <a href="/report.pdf">Report</a> <a href="/deep1">Deep</a>
    <a href="mailto:a@b.test">Mail</a> <a href="javascript:alert(1)">JS</a>
    <a href="/item?id=1&amp;token={QUERY_SECRET}">Item</a>
    <a href="/list?page=1">1</a><a href="/list?page=2">2</a><a href="/list?page=3">3</a>
    <a href="/list?page=4">4</a><a href="/list?page=5">5</a><a href="/list?page=6">6</a>
    <form action="/search" method="get"><input name="q"></form></body></html>"""


LOGIN_PAGE = """<html><title>Sign in</title><form action="/session" method="post">
<input type="hidden" name="csrf_token" value="abc"><input name="username" required>
<input type="password" name="password"><button name="go">Go</button></form>
<form action="/upload" method="post" enctype="multipart/form-data"><input type="file" name="doc"></form></html>"""
SCRIPT = """fetch("/api/users"); axios.post("/api/orders", {}); $.get("/api/status");
var x = new XMLHttpRequest(); x.open("PUT", "/api/items/7"); fetch(`/api/items/${id}/view`);"""
OPENAPI = {
    "openapi": "3.0.0",
    "paths": {
        "/api/v1/accounts/{accountId}": {
            "parameters": [{"name": "accountId", "in": "path", "required": True, "schema": {"type": "string"}}],
            "get": {"parameters": [{"name": "verbose", "in": "query", "schema": {"type": "boolean"}}]},
            "delete": {},
            "put": {"requestBody": {"content": {"application/json": {"schema": {
                "required": ["email"], "properties": {"email": {"type": "string"}}}}}}},
        }
    },
}


class Lab:
    """Serves the test site and records every request it receives."""

    def __init__(self):
        lab = self
        self.requests: list[dict] = []

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def _serve(self):
                lab.requests.append(
                    {"method": self.command, "path": self.path, "host": self.headers.get("Host"),
                     "address": self.server.server_address[0]}
                )
                path = self.path.split("?")[0]
                routes = {
                    "/": (200, "text/html", home_page(lab.port), {"Set-Cookie": f"sid={COOKIE_SECRET}; Path=/; HttpOnly; SameSite=Lax"}),
                    "/about": (200, "text/html", "<title>About</title><a href='/'>Home</a>", {}),
                    "/login": (200, "text/html", LOGIN_PAGE, {}),
                    "/admin": (302, "text/html", "", {"Location": "/login"}),
                    "/secure": (401, "text/html", "", {"WWW-Authenticate": "Basic"}),
                    "/forbidden": (403, "text/html", "", {}),
                    "/go": (302, "text/html", "", {"Location": f"http://127.0.0.2:{lab.port}/trap"}),
                    "/app.js": (200, "application/javascript", SCRIPT, {}),
                    "/robots.txt": (200, "text/plain", "User-agent: *\nDisallow: /hidden\nSitemap: /sitemap.xml\n", {}),
                    "/sitemap.xml": (200, "application/xml", '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>/from-sitemap</loc></url></urlset>', {}),
                    "/from-sitemap": (200, "text/html", "<title>Sitemap page</title>", {}),
                    "/openapi.json": (200, "application/json", json.dumps(OPENAPI), {}),
                    "/api/users": (200, "application/json", "[]", {"Allow": "GET, POST"}),
                    "/api/status": (200, "application/json", "{}", {}),
                    "/item": (200, "text/html", "<title>Item</title>", {}),
                    "/list": (200, "text/html", "<title>List</title>", {}),
                }
                for level in range(1, 8):
                    routes[f"/deep{level}"] = (200, "text/html", f"<a href='/deep{level + 1}'>next</a>", {})
                status, content_type, body, headers = routes.get(path, (404, "text/html", "missing", {}))
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                for key, value in headers.items():
                    self.send_header(key, value)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(data)

            do_GET = do_HEAD = do_OPTIONS = do_POST = do_PUT = do_DELETE = do_PATCH = _serve

            def log_message(self, *args):
                pass

        self.main = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.main.server_address[1]
        self.trap = ThreadingHTTPServer(("127.0.0.2", self.port), Handler)
        for server in (self.main, self.trap):
            threading.Thread(target=server.serve_forever, daemon=True).start()

    def close(self):
        for server in (self.main, self.trap):
            server.shutdown()
            server.server_close()

    def paths(self, method: str | None = None) -> list[str]:
        return [item["path"] for item in self.requests if method is None or item["method"] == method]


@pytest.fixture
def lab():
    server = Lab()
    yield server
    server.close()


@pytest.fixture
def mapping_engagement(lead, lab, app, tmp_path):
    app.config["JOB_DIR"] = tmp_path / "jobs"
    from app.services import settings

    settings.set_int("recon.rate_limit_rps", 100, lead)
    item = service.create_engagement(
        engagement_data(
            primary_target_url=f"http://127.0.0.1:{lab.port}/",
            authorized_scope=["127.0.0.1"],
            excluded_scope=[f"http://127.0.0.1:{lab.port}/private"],
            authorized_methods=["content_discovery"],
        ),
        lead,
    )
    service.confirm_authorization(item, lead, "SOW-3", "CISO")
    service.transition(item, "active", lead)
    db.session.commit()
    return item


def crawl(engagement, actor, modules=("app_crawl",), **options):
    job = jobs.create_mapping_job(engagement, actor, list(modules), options)
    db.session.commit()
    jobs.execute_job(jobs.claim_next_job())
    return db.session.get(ExecutionJob, job.id)


def endpoint(path: str, method: str = "GET") -> Endpoint | None:
    return db.session.scalar(db.select(Endpoint).filter_by(path=path, method=method))


class TestCrawlerSafety:
    def test_only_read_requests_are_ever_sent(self, mapping_engagement, lead, lab):
        crawl(mapping_engagement, lead, ("app_crawl", "api_discovery"))
        assert {item["method"] for item in lab.requests} <= {"GET", "OPTIONS"}

    def test_client_cannot_send_writes(self):
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            with pytest.raises(ValueError):
                client.fetch("http://127.0.0.1:1/", "127.0.0.1", method)

    def test_forms_are_recorded_but_never_submitted(self, mapping_engagement, lead, lab):
        crawl(mapping_engagement, lead)
        assert "/session" not in lab.paths() and "/upload" not in lab.paths()
        assert not any(path.startswith("/search") for path in lab.paths())
        assert endpoint("/session", "POST").crawl_state == "not_requested"

    def test_state_changing_links_are_recorded_but_never_requested(self, mapping_engagement, lead, lab):
        crawl(mapping_engagement, lead)
        for path in ("/logout", "/account/delete"):
            assert not any(item.startswith(path) for item in lab.paths())
            assert endpoint(path).crawl_state == "skipped_unsafe"

    def test_excluded_paths_are_never_requested(self, mapping_engagement, lead, lab):
        crawl(mapping_engagement, lead)
        assert not any(path.startswith("/private") for path in lab.paths())
        row = endpoint("/private/secret")
        assert row.in_scope is False and row.crawl_state == "out_of_scope"

    def test_other_hosts_and_redirects_are_never_contacted(self, mapping_engagement, lead, lab):
        crawl(mapping_engagement, lead)
        assert not any(item["address"] == "127.0.0.2" for item in lab.requests)
        redirect = endpoint("/go")
        assert redirect.status_code == 302 and "127.0.0.2" in redirect.redirect_location
        assert endpoint("/trap").in_scope is False

    def test_robots_rules_are_honored_by_default(self, mapping_engagement, lead, lab):
        crawl(mapping_engagement, lead)
        assert not any(path.startswith("/hidden") for path in lab.paths())
        assert endpoint("/hidden").crawl_state == "skipped_robots"

    def test_robots_can_be_turned_off_explicitly(self, mapping_engagement, lead, lab):
        crawl(mapping_engagement, lead, respect_robots=False)
        assert "/hidden/page" in lab.paths()

    def test_empty_robots_file_does_not_block_the_crawl(self, mapping_engagement, lead, lab, monkeypatch):
        import app.mapping.modules as module

        monkeypatch.setattr(module.extract, "parse_robots", lambda *_: extract.RobotsData([], []))
        crawl(mapping_engagement, lead)
        assert "/about" in lab.paths()

    def test_depth_limit(self, mapping_engagement, lead, lab):
        crawl(mapping_engagement, lead, max_depth=2)
        assert "/deep2" in lab.paths() and "/deep3" not in lab.paths()

    def test_request_limit(self, mapping_engagement, lead, lab):
        job = crawl(mapping_engagement, lead, max_pages=10)
        assert len(lab.requests) <= 12
        assert any("limit of 10 requests" in event.message for event in job.events)

    def test_query_variants_are_capped(self, mapping_engagement, lead, lab):
        crawl(mapping_engagement, lead)
        assert len([path for path in lab.paths() if path.startswith("/list?")]) == 3

    def test_rate_limit_is_applied(self, mapping_engagement, lead, lab):
        from app.services import settings

        settings.set_int("recon.rate_limit_rps", 20, lead)
        db.session.commit()
        started = time.monotonic()
        crawl(mapping_engagement, lead, max_pages=10)
        assert time.monotonic() - started >= (len(lab.requests) - 1) / 20

    def test_every_new_host_passes_the_audited_gate(self, mapping_engagement, lead, lab):
        crawl(mapping_engagement, lead)
        assert db.session.scalar(db.select(ActivityLog).filter_by(action="execution.gate", outcome="success"))

    def test_dns_rebinding_cannot_move_the_crawler(self, lead, lab, app, tmp_path, monkeypatch):
        app.config["JOB_DIR"] = tmp_path / "jobs"
        answers = iter([["127.0.0.1"]] + [["127.0.0.2"]] * 500)
        monkeypatch.setattr("app.services.scope.system_resolver", lambda _host: next(answers))
        item = service.create_engagement(
            engagement_data(
                primary_target_url=f"http://app.lab.test:{lab.port}/",
                authorized_scope=["app.lab.test", "127.0.0.1"],
                excluded_scope=[],
                authorized_methods=["content_discovery"],
            ),
            lead,
        )
        service.confirm_authorization(item, lead, "SOW", "CISO")
        service.transition(item, "active", lead)
        db.session.commit()
        crawl(item, lead)
        assert len(lab.requests) > 3
        assert all(request["address"] == "127.0.0.1" for request in lab.requests)
        assert all(request["host"].startswith("app.lab.test") for request in lab.requests)

    def test_crawl_stops_if_authorization_is_revoked(self, mapping_engagement, lead, lab, monkeypatch):
        import app.mapping.modules as module

        monkeypatch.setattr(module, "_PRECONDITION_INTERVAL", 1)
        original = module.fetch

        def revoke_after_first(*args):
            mapping_engagement.status = "paused"
            db.session.commit()
            return original(*args)

        monkeypatch.setattr(module, "fetch", revoke_after_first)
        job = crawl(mapping_engagement, lead)
        assert len(lab.requests) <= 3
        assert any("Stopped early" in event.message for event in job.events)

    def test_cancel_stops_the_crawl(self, mapping_engagement, lead, lab, monkeypatch):
        import app.mapping.modules as module

        original = module.fetch

        def cancel_after_first(*args):
            db.session.execute(db.update(ExecutionJob).values(cancel_requested=True))
            db.session.commit()
            return original(*args)

        monkeypatch.setattr(module, "fetch", cancel_after_first)
        job = crawl(mapping_engagement, lead)
        assert job.status == "cancelled" and len(lab.requests) <= 2
        assert db.session.scalar(db.select(ToolRun)).status == "cancelled"


class TestApplicationMap:
    @pytest.fixture
    def mapped(self, mapping_engagement, lead, lab):
        crawl(mapping_engagement, lead, ("app_crawl", "api_discovery"))
        return mapping_engagement

    def test_pages_and_titles(self, mapped):
        row = endpoint("/about")
        assert row.crawl_state == "fetched" and row.status_code == 200 and row.title == "About"

    def test_relationships_are_stored(self, mapped):
        link = db.session.scalar(
            db.select(EndpointLink).filter_by(source_id=endpoint("/").id, target_id=endpoint("/about").id)
        )
        assert link.link_type == "link"
        assert db.session.scalar(db.select(EndpointLink).filter_by(link_type="redirect", source_id=endpoint("/admin").id))
        assert db.session.scalar(db.select(EndpointLink).filter_by(link_type="form"))

    def test_forms_are_analyzed(self, mapped):
        login = db.session.scalar(db.select(WebForm).filter_by(purpose="authentication"))
        assert login.method == "POST" and login.has_password and login.has_csrf_token
        assert db.session.scalar(db.select(WebForm).filter_by(purpose="upload")).has_file_upload
        assert db.session.scalar(db.select(WebForm).filter_by(purpose="search")).method == "GET"

    def test_parameters_are_discovered_without_values(self, mapped):
        names = set(db.session.scalars(db.select(EndpointParameter.name)))
        assert {"id", "token", "q", "username", "password"} <= names
        dump = json.dumps([row.name for row in db.session.scalars(db.select(EndpointParameter))])
        assert QUERY_SECRET not in dump

    def test_sensitive_query_values_are_redacted_everywhere(self, mapped):
        row = endpoint("/item")
        assert "token=REDACTED" in row.url and "id=1" in row.url
        logs = [Path(run.output_path).read_text() for run in db.session.scalars(db.select(ToolRun))]
        assert logs and not any(QUERY_SECRET in text for text in logs)
        assert not any(QUERY_SECRET in url for url in db.session.scalars(db.select(Endpoint.url)))

    def test_hostile_link_floods_are_bounded(self, mapping_engagement, lead, lab, monkeypatch):
        import app.mapping.modules as module

        monkeypatch.setattr(module, "_MAX_RECORDED_ENDPOINTS", 5)
        crawl(mapping_engagement, lead)
        assert db.session.scalar(db.select(db.func.count()).select_from(Endpoint)) <= 12

    def test_cookie_attributes_are_stored_without_values(self, mapped):
        cookie = db.session.scalar(db.select(WebCookie).filter_by(name="sid"))
        assert cookie.http_only and not cookie.secure and cookie.same_site == "Lax"
        values = [str(value) for value in vars(cookie).values()]
        assert not any(COOKIE_SECRET in value for value in values)

    def test_authentication_protection_is_detected(self, mapped):
        assert endpoint("/secure").requires_auth is True
        assert endpoint("/forbidden").requires_auth is True
        assert endpoint("/admin").requires_auth is True
        assert endpoint("/about").requires_auth is False

    def test_endpoints_are_categorized(self, mapped):
        assert endpoint("/login").category == "authentication"
        assert endpoint("/admin").category == "administration"
        assert endpoint("/api/users").category == "api"
        assert endpoint("/upload", "POST").category == "file_upload"

    def test_javascript_routes_and_methods_are_found(self, mapped):
        assert endpoint("/api/users").crawl_state == "fetched"
        assert endpoint("/api/orders", "POST").crawl_state == "not_requested"
        assert endpoint("/api/items/7", "PUT").crawl_state == "not_requested"
        assert endpoint("/api/inline", "POST") is not None
        assert endpoint("/api/items/{param}/view") is not None

    def test_sitemap_pages_are_crawled(self, mapped):
        assert endpoint("/from-sitemap").crawl_state == "fetched"

    def test_static_files_are_listed_but_not_downloaded(self, mapped, lab):
        assert endpoint("/report.pdf").crawl_state == "skipped_static" and "/report.pdf" not in lab.paths()

    def test_openapi_routes_are_imported_and_not_called(self, mapped, lab):
        target = "/api/v1/accounts/{accountId}"
        assert endpoint(target, "DELETE").crawl_state == "not_requested"
        assert not any("accounts" in path for path in lab.paths())
        parameters = {row.name: row for row in db.session.scalars(
            db.select(EndpointParameter).filter_by(endpoint_id=endpoint(target, "PUT").id))}
        assert parameters["accountId"].location == "path" and parameters["accountId"].required
        assert parameters["email"].location == "json" and parameters["email"].required

    def test_allowed_methods_are_identified(self, mapped):
        assert endpoint("/api/users").allowed_methods == "GET, POST"

    def test_second_crawl_does_not_duplicate(self, mapped, lead):
        before = db.session.scalar(db.select(db.func.count()).select_from(Endpoint))
        crawl(mapped, lead, ("app_crawl", "api_discovery"))
        assert db.session.scalar(db.select(db.func.count()).select_from(Endpoint)) == before


class TestClientLimits:
    @pytest.fixture
    def server(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                if self.path == "/big":
                    self.end_headers()
                    try:
                        for _ in range(100):
                            self.wfile.write(b"x" * 1024 * 1024)
                    except OSError:
                        pass
                elif self.path == "/gzip":
                    self.send_header("Content-Encoding", "gzip")
                    self.end_headers()
                    self.wfile.write(gzip.compress(b"a" * 1024 * 1024))
                elif self.path == "/drip":
                    self.end_headers()
                    try:
                        for _ in range(100):
                            self.wfile.write(b"x")
                            self.wfile.flush()
                            time.sleep(0.2)
                    except OSError:
                        pass

            def log_message(self, *args):
                pass

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        httpd.daemon_threads = True
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
        httpd.shutdown()

    def test_large_responses_are_truncated(self, server):
        response = client.fetch(f"{server}/big", "127.0.0.1")
        assert response.truncated and len(response.body) == client.MAX_BODY_BYTES

    def test_compressed_bodies_are_never_expanded(self, server):
        assert client.fetch(f"{server}/gzip", "127.0.0.1").text == ""

    def test_slow_responses_hit_the_deadline(self, server, monkeypatch):
        monkeypatch.setattr(client, "TOTAL_DEADLINE_SECONDS", 1)
        started = time.monotonic()
        assert client.fetch(f"{server}/drip", "127.0.0.1").truncated
        assert time.monotonic() - started < 5

    def test_connection_failure_is_reported(self):
        with pytest.raises(client.FetchError):
            client.fetch("http://127.0.0.1:1/", "127.0.0.1")


class TestExtraction:
    BASE = "http://a.test/dir/page"

    @pytest.mark.parametrize(
        "href,expected",
        [
            ("x", "http://a.test/dir/x"), ("/y", "http://a.test/y"), ("#frag", "http://a.test/dir/page"),
            ("//b.test/z", "http://b.test/z"), ("javascript:alert(1)", None), ("mailto:a@b.c", None),
            ("data:text/html,x", None), ("file:///etc/passwd", None), ("http://[bad", None), ("", None),
            ("a\nb", None), ("http://a.test:99999/", None),
        ],
    )
    def test_normalize_link(self, href, expected):
        assert extract.normalize_link(self.BASE, href) == expected

    def test_base_tag_changes_resolution(self):
        page = extract.parse_page(self.BASE, '<base href="/root/"><a href="x">x</a>')
        assert "http://a.test/root/x" in page.links

    @pytest.mark.parametrize(
        "html",
        ["<a href=", "<<<<>>>>", "<form><input name=", "\x00\x01<a", "<script>" * 5000, "<div>" * 50000,
         "<!-- unclosed", "<![CDATA[", "&#xFFFFFFFF;"],
    )
    def test_malformed_html_does_not_crash(self, html):
        assert isinstance(extract.parse_page(self.BASE, html), extract.PageData)

    def test_link_and_form_counts_are_bounded(self):
        html = "".join(f'<a href="/{i}">x</a><form></form>' for i in range(extract.MAX_LINKS + 100))
        page = extract.parse_page(self.BASE, html)
        assert len(page.links) == extract.MAX_LINKS and len(page.forms) == extract.MAX_FORMS

    @pytest.mark.parametrize(
        "header,name,secure,http_only,same_site",
        [
            ("a=1; Secure; HttpOnly; SameSite=Strict", "a", True, True, "Strict"),
            ("b=2", "b", False, False, ""),
            ("c=3; path=/x; HTTPONLY", "c", False, True, ""),
        ],
    )
    def test_set_cookie(self, header, name, secure, http_only, same_site):
        cookie = extract.parse_set_cookie(header)
        assert (cookie.name, cookie.secure, cookie.http_only, cookie.same_site) == (name, secure, http_only, same_site)

    @pytest.mark.parametrize("header", ["", "novalue", "=x"])
    def test_invalid_cookies_are_ignored(self, header):
        assert extract.parse_set_cookie(header) is None

    @pytest.mark.parametrize(
        "payload",
        ['<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><urlset><loc>&e;</loc></urlset>',
         '<!DOCTYPE x [<!ENTITY a "aa"><!ENTITY b "&a;&a;">]><urlset><loc>&b;</loc></urlset>', "not xml"],
    )
    def test_hostile_sitemaps_are_rejected(self, payload):
        assert extract.parse_sitemap(self.BASE, payload) == []

    @pytest.mark.parametrize("payload", ["", "[]", "{}", '{"openapi":"3"}', '{"openapi":"3","paths":[]}', "[" * 100000])
    def test_invalid_api_definitions_are_ignored(self, payload):
        assert extract.parse_openapi("http://a.test", payload) is None

    def test_malformed_api_operations_are_skipped(self):
        spec = {"openapi": "3", "paths": {"/ok": {"get": {}}, "/bad": 5, "/worse": {"get": 7, "parameters": "x"}}}
        assert [item.url for item in extract.parse_openapi("http://a.test", json.dumps(spec))] == ["http://a.test/ok"]


class TestClassification:
    @pytest.mark.parametrize(
        "url",
        ["http://a/logout", "http://a/log-out", "http://a/signOut", "http://a/user/delete/5", "http://a/deleteUser",
         "http://a/DELETE", "http://a/x?action=delete", "http://a/x?do=remove", "http://a/cart/checkout",
         "http://a/pay", "http://a/order?confirm=1", "http://a/unsubscribe?u=1", "http://a/password/reset"],
    )
    def test_unsafe_links(self, url):
        assert classify.is_unsafe_url(url)

    @pytest.mark.parametrize(
        "url",
        ["http://a/", "http://a/about", "http://a/products/12", "http://a/blog?page=2", "http://a/orders",
         "http://a/runner", "http://a/payments-faq"],
    )
    def test_safe_links(self, url):
        assert not classify.is_unsafe_url(url)

    @pytest.mark.parametrize(
        "url,category",
        [("http://a/login", "authentication"), ("http://a/admin/users", "administration"),
         ("http://a/api/v1/x", "api"), ("http://a/graphql", "graphql"), ("http://a/upload", "file_upload"),
         ("http://a/billing", "payment"), ("http://a/profile", "user_account"), ("http://a/search", "search"),
         ("http://a/.git/config", "diagnostics"), ("http://a/logo.png", "static"), ("http://a/about", "content")],
    )
    def test_categories(self, url, category):
        assert classify.categorize(url) == category


class TestMappingPages:
    @pytest.fixture
    def mapped(self, mapping_engagement, lead, lab):
        crawl(mapping_engagement, lead, ("app_crawl", "api_discovery"))
        return mapping_engagement

    def test_pages_render(self, client, login, mapped):
        login("lead.tester")
        for tab in ("endpoints", "structure", "forms", "parameters", "cookies"):
            assert client.get(f"/mapping/?engagement={mapped.id}&tab={tab}").status_code == 200, tab
        assert client.get(f"/mapping/engagements/{mapped.id}/new").status_code == 200
        assert b"Linked from" in client.get(f"/mapping/endpoints/{endpoint('/about').id}").data

    def test_filters(self, client, login, mapped):
        login("lead.tester")
        body = client.get(f"/mapping/?engagement={mapped.id}&category=authentication").data
        assert b"/login" in body and b"/about" not in body.split(b"<tbody>")[1]
        assert client.get(f"/mapping/?engagement={mapped.id}&q=%27%20OR%201%3D1").status_code == 200

    def test_start_requires_confirmation(self, client, login, mapping_engagement):
        login("lead.tester")
        client.post(f"/mapping/engagements/{mapping_engagement.id}/new", data={"modules": ["app_crawl"]})
        assert db.session.scalar(db.select(ExecutionJob)) is None

    def test_start_through_ui_clamps_limits(self, client, login, mapping_engagement, lab):
        login("lead.tester")
        response = client.post(
            f"/mapping/engagements/{mapping_engagement.id}/new",
            data={"modules": ["app_crawl"], "confirm": "y", "max_depth": 9999, "max_pages": 999999, "respect_robots": "y"},
        )
        assert response.status_code == 302
        job = jobs.claim_next_job()
        jobs.execute_job(job)
        run = db.session.scalar(db.select(ToolRun))
        assert "max_depth=10" in run.arguments and "max_requests=5000" in run.arguments

    def test_requires_authorized_method(self, lead, lab):
        item = service.create_engagement(
            engagement_data(
                primary_target_url=f"http://127.0.0.1:{lab.port}/", authorized_scope=["127.0.0.1"],
                excluded_scope=[], authorized_methods=["active_recon"],
            ),
            lead,
        )
        service.confirm_authorization(item, lead, "SOW", "CISO")
        service.transition(item, "active", lead)
        with pytest.raises(jobs.JobError, match="not authorized"):
            jobs.create_mapping_job(item, lead, ["app_crawl"], {})

    def test_unassigned_user_gets_404(self, client, login, make_user, mapped):
        make_user("outsider")
        login("outsider")
        for path in (f"/mapping/?engagement={mapped.id}", f"/mapping/endpoints/{endpoint('/about').id}",
                     f"/mapping/engagements/{mapped.id}/new"):
            assert client.get(path).status_code == 404, path

    def test_read_only_role_cannot_start_a_crawl(self, client, login, make_user, mapped):
        make_user("auditor.two", "Auditor")
        login("auditor.two")
        path = f"/mapping/engagements/{mapped.id}/new"
        assert client.post(path, data={"modules": ["app_crawl"], "confirm": "y"}).status_code == 403

    def test_hostile_page_content_is_escaped(self, client, login, mapped):
        payload = "<script>alert(1)</script>"
        row = endpoint("/about")
        row.title = payload
        db.session.commit()
        login("lead.tester")
        for path in (f"/mapping/?engagement={mapped.id}", f"/mapping/endpoints/{row.id}"):
            body = client.get(path).data
            assert payload.encode() not in body and b"&lt;script&gt;" in body
