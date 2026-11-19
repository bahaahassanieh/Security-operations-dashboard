"""Shared fixtures. Every test gets a fresh file-backed SQLite database."""
from __future__ import annotations

from datetime import date, timedelta

import pytest
from flask import g
from flask.testing import FlaskClient

from app import create_app
from app.extensions import db
from app.models import Role, User
from app.services import accounts, authz
from app.services import engagements as service

PASSWORD = "Correct-Horse-42-Battery"


class IsolatedClient(FlaskClient):
    """Fixtures hold an app context open, so reset per-request state as a real server would."""

    def open(self, *args, **kwargs):
        g.pop("_login_user", None)
        db.session.flush()
        db.session.expire_all()
        return super().open(*args, **kwargs)


@pytest.fixture
def app(tmp_path):
    application = create_app(
        "testing",
        {
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'test.db'}",
            "BACKUP_DIR": tmp_path / "backups",
            "IMPORT_DIR": tmp_path / "imports",
        },
    )
    application.test_client_class = IsolatedClient
    with application.app_context():
        db.create_all()
        authz.seed_rbac()
        yield application
        db.session.remove()
        db.engine.dispose()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def make_user(app):
    def _make(username: str, role_name: str = "Penetration Tester", **kwargs) -> User:
        role = db.session.scalar(db.select(Role).filter_by(name=role_name))
        user, _ = accounts.create_user(
            username, f"{username}@example.test", username.title(), role, PASSWORD,
            must_change_password=kwargs.get("must_change_password", False),
        )
        db.session.commit()
        return user

    return _make


@pytest.fixture
def login(client):
    def _login(username: str, password: str = PASSWORD, target=None):
        return (target or client).post(
            "/login", data={"username": username, "password": password}
        )

    return _login


@pytest.fixture
def admin(make_user):
    return make_user("root.admin", "Administrator")


@pytest.fixture
def lead(make_user):
    return make_user("lead.tester", "Lead Tester")


def engagement_data(**overrides) -> service.EngagementData:
    today = date.today()
    values = {
        "name": "Acme Portal",
        "client_name": "Acme",
        "primary_target_url": "https://app.acme-corp.test/",
        "start_date": today - timedelta(days=1),
        "end_date": today + timedelta(days=7),
        "authorized_scope": ["app.acme-corp.test", "*.staging.acme-corp.test", "203.0.113.0/24"],
        "excluded_scope": ["pay.staging.acme-corp.test", "203.0.113.9"],
        "authorized_methods": ["active_recon", "automated_scanning"],
        "rules_of_engagement": "No denial of service.",
    }
    values.update(overrides)
    return service.EngagementData(**values)


@pytest.fixture
def engagement(lead):
    item = service.create_engagement(engagement_data(), lead)
    db.session.commit()
    return item


@pytest.fixture
def active_engagement(engagement, lead):
    service.confirm_authorization(engagement, lead, "SOW-1", "Jane Client, CISO")
    service.transition(engagement, "active", lead)
    db.session.commit()
    return engagement
