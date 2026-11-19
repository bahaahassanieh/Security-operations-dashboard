"""Platform hardening: CSRF, headers, access control, sessions, XSS and redirects."""
from __future__ import annotations

import re

import pytest

from app import create_app
from app.blueprints.auth import safe_next_url
from app.extensions import db
from app.models import ActivityLog
from app.services import authz
from tests.conftest import PASSWORD, engagement_data
from app.services import engagements as service


def test_security_headers_present(client):
    response = client.get("/login")
    csp = response.headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp and "script-src 'self'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"


def test_templates_contain_no_inline_script_or_style(app):
    from pathlib import Path

    root = Path(app.root_path) / "templates"
    for template in root.rglob("*.html"):
        # Report documents are standalone, downloadable artifacts, not app pages under the CSP.
        if "documents" in template.parts:
            continue
        text = template.read_text()
        assert not re.search(r"<script(?![^>]*\bsrc=)", text), template
        assert not re.search(r"\sstyle=", text), template
        assert not re.search(r"\son[a-z]+=", text), template
        assert "|safe" not in text, template


@pytest.mark.parametrize(
    "host,expected",
    [("evil.test", 400), ("localhost.evil.test", 400), ("localhost", 200), ("localhost:8088", 200),
     ("127.0.0.1:8088", 200), ("[::1]:8088", 200)],
)
def test_untrusted_hosts_are_rejected(tmp_path, host, expected):
    application = create_app(
        "testing",
        {
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'hosts.db'}",
            "ALLOWED_HOSTS": ["localhost", "127.0.0.1", "[::1]"],
        },
    )
    response = application.test_client().get("/healthz", headers={"Host": host})
    assert response.status_code == expected


def test_session_cookie_flags(client, make_user, login):
    make_user("cookie.user")
    response = login("cookie.user")
    cookie = response.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie


@pytest.mark.parametrize(
    "target",
    ["https://evil.test/", "//evil.test/", "/\\evil.test", "http:evil.test", "javascript:alert(1)",
     "/ok\r\nSet-Cookie: x=1", ""],
)
def test_open_redirects_are_blocked(app, target):
    with app.test_request_context():
        assert safe_next_url(target) == "/"


def test_relative_next_is_preserved(app):
    with app.test_request_context():
        assert safe_next_url("/engagements/?q=a") == "/engagements/?q=a"


class TestCsrf:
    @pytest.fixture
    def csrf_client(self, tmp_path):
        application = create_app(
            "testing",
            {
                "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'csrf.db'}",
                "WTF_CSRF_ENABLED": True,
            },
        )
        with application.app_context():
            db.create_all()
            authz.seed_rbac()
            yield application.test_client()
            db.session.remove()
            db.engine.dispose()

    def test_login_without_token_is_rejected(self, csrf_client):
        response = csrf_client.post("/login", data={"username": "a", "password": "b"})
        assert response.status_code == 400

    def test_api_write_without_token_is_rejected(self, csrf_client):
        response = csrf_client.post("/api/v1/engagements/1/scope-check", json={"target": "x"})
        assert response.status_code == 400
        assert response.get_json()["error"] == "csrf_failed"


class TestObjectLevelAccess:
    """A tester must not reach engagements they are not assigned to."""

    @pytest.fixture
    def outsider(self, make_user, login):
        make_user("outsider")
        login("outsider")

    @pytest.mark.parametrize(
        "method,path",
        [
            ("get", "/engagements/{id}"),
            ("post", "/engagements/{id}/scope-check"),
            ("get", "/api/v1/engagements/{id}"),
            ("post", "/api/v1/engagements/{id}/scope-check"),
        ],
    )
    def test_unassigned_user_gets_404(self, client, engagement, outsider, method, path):
        url = path.format(id=engagement.id)
        kwargs = {"json": {"target": "app.acme-corp.test"}} if "api" in path and method == "post" else {}
        assert getattr(client, method)(url, **kwargs).status_code == 404

    def test_listing_hides_unassigned_engagements(self, client, engagement, outsider):
        assert client.get("/api/v1/engagements").get_json()["total"] == 0
        assert engagement.name.encode() not in client.get("/engagements/").data

    def test_dashboard_hides_unassigned_engagements(self, client, engagement, outsider):
        assert client.get("/api/v1/dashboard/summary").get_json()["engagements"]["total"] == 0

    def test_denied_access_is_audited(self, client, engagement, outsider):
        client.get(f"/engagements/{engagement.id}")
        entry = db.session.scalar(
            db.select(ActivityLog).filter_by(action="authz.denied", outcome="denied")
        )
        assert entry is not None and entry.object_id == str(engagement.id)

    def test_assigned_tester_has_access(self, client, make_user, login, lead):
        tester = make_user("assigned")
        item = service.create_engagement(engagement_data(tester_ids=[tester.id]), lead)
        db.session.commit()
        login("assigned")
        assert client.get(f"/engagements/{item.id}").status_code == 200


class TestVerticalAccess:
    @pytest.mark.parametrize(
        "path",
        ["/admin/users", "/admin/roles", "/admin/settings", "/admin/users/new", "/audit/",
         "/engagements/new"],
    )
    def test_tester_cannot_reach_privileged_pages(self, client, make_user, login, path):
        make_user("limited")
        login("limited")
        assert client.get(path).status_code == 403

    @pytest.mark.parametrize("path", ["/", "/engagements/", "/admin/users", "/audit/"])
    def test_anonymous_is_redirected_to_login(self, client, path):
        response = client.get(path)
        assert response.status_code == 302 and "/login" in response.location

    def test_anonymous_api_gets_401(self, client):
        assert client.get("/api/v1/engagements").status_code == 401

    def test_viewer_cannot_authorize(self, client, make_user, login, engagement):
        make_user("viewer", "Auditor")
        login("viewer")
        response = client.post(
            f"/engagements/{engagement.id}/authorize",
            data={"authorization_reference": "x", "authorization_signatory": "y", "confirm": "y"},
        )
        assert response.status_code == 403


class TestSessions:
    def test_logout_invalidates_copied_cookie(self, app, client, make_user, login):
        make_user("copycat")
        login("copycat")
        stolen = client.get_cookie("ptp_session").value
        client.post("/logout")
        attacker = app.test_client()
        attacker.set_cookie("ptp_session", stolen)
        assert attacker.get("/").status_code == 302

    def test_disabling_user_ends_session(self, client, make_user, login):
        user = make_user("soon.gone")
        login("soon.gone")
        assert client.get("/").status_code == 200
        user.is_enabled = False
        db.session.commit()
        assert client.get("/").status_code == 302

    def test_temporary_password_forces_change(self, client, make_user, login):
        make_user("newbie", must_change_password=True)
        login("newbie")
        response = client.get("/engagements/")
        assert response.status_code == 302 and "/account/password" in response.location
        assert client.get("/api/v1/engagements").status_code == 403


def test_stored_xss_is_escaped(client, login, lead):
    payload = "<script>alert(1)</script>"
    item = service.create_engagement(
        engagement_data(name=payload, client_name=payload, description=payload), lead
    )
    db.session.commit()
    login("lead.tester")
    for path in (f"/engagements/{item.id}", "/engagements/"):
        body = client.get(path).data
        assert payload.encode() not in body
        assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in body


def test_search_treats_sql_as_data(client, login, engagement):
    login("lead.tester")
    response = client.get("/engagements/", query_string={"q": "' OR 1=1 --"})
    assert response.status_code == 200
    assert engagement.name.encode() not in response.data


def test_passwords_never_reach_the_audit_log(client, make_user, login):
    make_user("secretive")
    login("secretive", "Wrong-Password-123!")
    login("secretive", PASSWORD)
    for entry in db.session.scalars(db.select(ActivityLog)):
        assert "Wrong-Password" not in entry.details and PASSWORD not in entry.details


def test_target_credentials_never_reach_the_audit_log(client, login, engagement):
    login("lead.tester")
    client.post(
        f"/api/v1/engagements/{engagement.id}/scope-check",
        json={"target": "https://bob:hunter2@app.acme-corp.test/x?token=abc123"},
    )
    entry = db.session.scalar(db.select(ActivityLog).filter_by(action="scope.check"))
    assert "hunter2" not in entry.details and "abc123" not in entry.details


def test_password_typed_as_username_is_not_logged(client, login):
    login("My Secret Passphrase!", "whatever")
    entry = db.session.scalar(db.select(ActivityLog).filter_by(action="auth.login"))
    assert "Passphrase" not in entry.details


def test_errors_do_not_leak_internals(app, client, make_user, login, monkeypatch):
    make_user("erroring")
    login("erroring")
    monkeypatch.setattr(
        "app.blueprints.dashboard.build_summary",
        lambda _user: (_ for _ in ()).throw(RuntimeError("secret internal detail")),
    )
    response = client.get("/")
    assert response.status_code == 500 and b"secret internal detail" not in response.data
