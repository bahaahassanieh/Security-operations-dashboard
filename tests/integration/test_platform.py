"""Authentication, administration, audit, dashboard, migrations and backups."""
from __future__ import annotations

import sqlite3
from datetime import timedelta

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from flask_migrate import upgrade
from sqlalchemy import inspect, text
from sqlalchemy.exc import DBAPIError, IntegrityError

from app import create_app
from app.extensions import db
from app.models import (
    ActivityLog,
    Remediation,
    Role,
    Subdomain,
    User,
    Vulnerability,
    utcnow,
)
from app.services import accounts, audit, authz, backup, settings
from tests.conftest import PASSWORD

REQUIRED_TABLES = {
    "users", "roles", "permissions", "engagements", "engagement_scope", "targets", "assets",
    "subdomains", "endpoints", "technologies", "test_cases", "test_executions", "tool_registry",
    "vulnerabilities", "evidence", "reports", "remediation", "retests", "activity_logs",
    "execution_jobs", "application_settings",
}


class TestAuthentication:
    def test_login_and_logout(self, client, make_user, login):
        make_user("alice")
        assert login("alice").status_code == 302
        assert client.get("/").status_code == 200
        client.post("/logout")
        assert client.get("/").status_code == 302

    def test_logout_requires_post(self, client, make_user, login):
        make_user("alice")
        login("alice")
        assert client.get("/logout").status_code == 405

    def test_same_message_for_unknown_user_and_bad_password(self, client, make_user, login):
        make_user("alice")
        unknown = login("nobody", "Wrong-Password-1!")
        wrong = login("alice", "Wrong-Password-1!")
        assert unknown.status_code == wrong.status_code == 200
        assert b"Invalid username or password" in unknown.data
        assert b"Invalid username or password" in wrong.data

    def test_account_locks_after_repeated_failures(self, client, make_user, login):
        user = make_user("alice")
        for _ in range(settings.get_int("auth.max_failed_logins")):
            login("alice", "Wrong-Password-1!")
        db.session.refresh(user)
        assert user.is_locked
        login("alice")  # The correct password must not work while locked.
        assert client.get("/").status_code == 302

    def test_lock_expires(self, client, make_user, login):
        user = make_user("alice")
        user.locked_until = utcnow() - timedelta(seconds=1)
        db.session.commit()
        login("alice")
        assert client.get("/").status_code == 200

    def test_disabled_account_cannot_login(self, client, make_user, login):
        user = make_user("alice")
        user.is_enabled = False
        db.session.commit()
        login("alice")
        assert client.get("/").status_code == 302

    def test_password_is_hashed_with_argon2id(self, make_user):
        assert make_user("alice").password_hash.startswith("$argon2id$")

    @pytest.mark.parametrize(
        "password", ["short1A!", "alllowercaseletters", "Alice-Password-123!"]
    )
    def test_weak_passwords_are_rejected(self, app, password):
        with pytest.raises(accounts.AccountError):
            accounts.validate_password_strength(password, "alice")

    def test_password_change_revokes_other_sessions(self, app, client, make_user, login):
        make_user("alice")
        other = app.test_client()
        login("alice", target=other)
        login("alice")
        new_password = "Another-Strong-Pass-77"
        response = client.post(
            "/account/password",
            data={
                "current_password": PASSWORD,
                "new_password": new_password,
                "confirm_password": new_password,
            },
        )
        assert response.status_code == 302
        assert client.get("/").status_code == 200
        assert other.get("/").status_code == 302


class TestAdministration:
    def test_admin_creates_user_and_sees_one_time_password(self, client, login, admin):
        login("root.admin")
        role = db.session.scalar(db.select(Role).filter_by(name="Penetration Tester"))
        response = client.post(
            "/admin/users/new",
            data={"username": "new.user", "email": "new@example.test", "role_id": role.id,
                  "is_enabled": "y"},
        )
        assert response.status_code == 200 and b"One-time password" in response.data
        assert db.session.scalar(db.select(User).filter_by(username="new.user")).must_change_password

    def test_last_admin_cannot_be_demoted(self, make_user, admin):
        other = make_user("other.admin", "Administrator")
        tester_role = db.session.scalar(db.select(Role).filter_by(name="Penetration Tester"))
        other.is_enabled = False
        db.session.flush()
        with pytest.raises(accounts.AccountError):
            accounts.update_user(admin, other, email=admin.email, full_name="", role=tester_role, enabled=True)

    def test_admin_cannot_disable_self(self, admin):
        with pytest.raises(accounts.AccountError):
            accounts.update_user(admin, admin, email=admin.email, full_name="", role=admin.role, enabled=False)

    def test_role_change_takes_effect_and_is_audited(self, client, login, admin):
        login("root.admin")
        role = db.session.scalar(db.select(Role).filter_by(name="Client Viewer"))
        permission = next(item for item in role.permissions if item.code == "reports.view")
        client.post("/admin/roles", data={f"role-{role.id}": [str(permission.id)]})
        db.session.refresh(role)
        assert role.permission_codes() == {"reports.view"}
        assert db.session.scalar(
            db.select(ActivityLog).filter_by(action="role.permissions_changed")
        )

    def test_locked_administrator_role_cannot_be_reduced(self, client, login, admin):
        login("root.admin")
        client.post("/admin/roles", data={})
        assert admin.role.permission_codes() == set(authz.PERMISSIONS)

    def test_settings_are_validated(self, client, login, admin):
        login("root.admin")
        data = {key: definition.default for key, definition in settings.DEFINITIONS.items()}
        data["auth.max_failed_logins"] = 9999
        client.post("/admin/settings", data=data)
        assert settings.get_int("auth.max_failed_logins") == 5
        data["auth.max_failed_logins"] = 7
        client.post("/admin/settings", data=data)
        assert settings.get_int("auth.max_failed_logins") == 7


class TestAuditTrail:
    def test_chain_verifies(self, make_user, login):
        make_user("alice")
        login("alice")
        status = audit.verify_chain()
        assert status.valid and status.entries_checked >= 2

    def test_update_and_delete_are_blocked_by_triggers(self, make_user):
        make_user("alice")
        with pytest.raises(DBAPIError):
            db.session.execute(text("UPDATE activity_logs SET actor_name = 'mallory'"))
        db.session.rollback()
        with pytest.raises(DBAPIError):
            db.session.execute(text("DELETE FROM activity_logs"))
        db.session.rollback()

    @pytest.mark.parametrize(
        "statement",
        [
            "UPDATE activity_logs SET details = '{}' WHERE id = 2",
            "UPDATE activity_logs SET outcome = 'denied' WHERE id = 1",
            "DELETE FROM activity_logs WHERE id = 2",
        ],
    )
    def test_tampering_is_detected(self, make_user, statement):
        make_user("alice")
        make_user("bob")
        make_user("carol")
        db.session.execute(text("DROP TRIGGER trg_activity_logs_no_update"))
        db.session.execute(text("DROP TRIGGER trg_activity_logs_no_delete"))
        db.session.execute(text(statement))
        db.session.commit()
        assert not audit.verify_chain().valid

    def test_forged_entry_without_key_is_detected(self, app, make_user):
        make_user("alice")
        app.config["AUDIT_HMAC_KEY"] = "attacker-does-not-know-the-real-key-0000"
        assert not audit.verify_chain().valid

    def test_sensitive_details_are_redacted(self):
        result = audit.redact({"password": "x", "nested": {"api_key": "y"}, "safe": 1})
        assert result == {"password": "[REDACTED]", "nested": {"api_key": "[REDACTED]"}, "safe": 1}

    def test_audit_page_and_verify(self, client, login, admin):
        login("root.admin")
        assert b"auth.login" in client.get("/audit/").data
        assert b"Audit chain is intact" in client.post("/audit/verify", follow_redirects=True).data


class TestDashboard:
    @staticmethod
    def finding(engagement, uid, severity, status="detected"):
        return Vulnerability(
            finding_uid=uid, engagement_id=engagement.id, name=f"Issue {uid}",
            vulnerability_type="xss", severity=severity, validation_status=status,
            dedup_fingerprint=uid,
        )

    def test_empty_dashboard_renders(self, client, make_user, login):
        make_user("alice")
        login("alice")
        assert client.get("/").status_code == 200
        assert client.get("/api/v1/dashboard/summary").get_json()["findings"]["total"] == 0

    def test_metrics_are_accurate(self, client, login, engagement):
        rows = [
            self.finding(engagement, "F1", "critical", "confirmed"),
            self.finding(engagement, "F2", "high", "detected"),
            self.finding(engagement, "F3", "high", "needs_manual_review"),
            self.finding(engagement, "F4", "low", "false_positive"),
        ]
        db.session.add_all(rows)
        db.session.add(Subdomain(engagement_id=engagement.id, hostname="a.acme-corp.test"))
        db.session.flush()
        db.session.add_all(
            [Remediation(vulnerability_id=rows[0].id, status="verified"),
             Remediation(vulnerability_id=rows[1].id, status="open")]
        )
        db.session.commit()
        login("lead.tester")
        data = client.get("/api/v1/dashboard/summary").get_json()
        assert data["findings"]["total"] == 3
        assert data["findings"]["severity"]["high"] == 2
        assert data["findings"]["severity"]["low"] == 0
        assert data["findings"]["confirmed"] == 1
        assert data["findings"]["unconfirmed"] == 2
        assert data["findings"]["false_positive"] == 1
        assert data["assets"]["domains"] == 1
        assert data["remediation"] == {"total": 2, "done": 1, "percent": 50}
        assert data["most_vulnerable"][0]["risk_score"] == 22


@pytest.mark.usefixtures("app")
class TestSchema:
    def test_all_required_tables_exist(self):
        assert REQUIRED_TABLES <= set(inspect(db.engine).get_table_names())

    def test_foreign_keys_are_enforced(self):
        with pytest.raises(IntegrityError):
            db.session.execute(
                text("INSERT INTO targets (engagement_id, url, host, label, is_primary, created_at, "
                     "updated_at) VALUES (9999, 'u', 'h', '', 0, '2026-01-01', '2026-01-01')")
            )
        db.session.rollback()

    def test_check_constraints_are_enforced(self, engagement):
        db.session.add(
            Vulnerability(
                finding_uid="X", engagement_id=engagement.id, name="n", vulnerability_type="t",
                severity="catastrophic", dedup_fingerprint="d",
            )
        )
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()

    def test_new_findings_default_to_unconfirmed(self, engagement):
        finding = TestDashboard.finding(engagement, "F9", "high")
        del finding.validation_status
        db.session.add(finding)
        db.session.commit()
        assert finding.validation_status == "detected"

    def test_wal_mode_is_enabled(self):
        assert db.session.execute(text("PRAGMA journal_mode")).scalar() == "wal"


@pytest.fixture
def migrated_app(tmp_path):
    application = create_app(
        "testing",
        {
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'migrated.db'}",
            "BACKUP_DIR": tmp_path / "backups",
        },
    )
    with application.app_context():
        upgrade()
        yield application
        db.session.remove()
        db.engine.dispose()


class TestMigrations:
    def test_migration_matches_models(self, migrated_app):
        with db.engine.connect() as connection:
            context = MigrationContext.configure(connection, opts={"compare_type": True})
            assert compare_metadata(context, db.metadata) == []

    def test_migration_installs_audit_triggers(self, migrated_app):
        names = db.session.execute(
            text("SELECT name FROM sqlite_master WHERE type = 'trigger'")
        ).scalars().all()
        assert {"trg_activity_logs_no_update", "trg_activity_logs_no_delete"} <= set(names)

    def test_readiness_probe(self, migrated_app):
        assert migrated_app.test_client().get("/readyz").status_code == 200


class TestBackup:
    def seed(self):
        authz.seed_rbac()
        role = db.session.scalar(db.select(Role).filter_by(name="Administrator"))
        accounts.create_user("keeper", "keeper@example.test", "", role, PASSWORD)
        db.session.commit()

    def test_backup_and_restore_roundtrip(self, migrated_app):
        self.seed()
        path = backup.create_backup()
        assert oct(path.stat().st_mode)[-3:] == "600"
        user = db.session.scalar(db.select(User).filter_by(username="keeper"))
        user.full_name = "Changed after backup"
        db.session.commit()
        db.session.remove()
        db.engine.dispose()

        safety = backup.restore_backup(path)
        assert safety.exists()
        restored = db.session.scalar(db.select(User).filter_by(username="keeper"))
        assert restored.full_name == ""
        assert audit.verify_chain().valid

    def test_modified_backup_is_refused(self, migrated_app):
        self.seed()
        path = backup.create_backup()
        with path.open("ab") as handle:
            handle.write(b"tampered")
        with pytest.raises(backup.BackupError, match="Checksum"):
            backup.restore_backup(path)

    def test_non_database_file_is_refused(self, migrated_app, tmp_path):
        fake = tmp_path / "fake.db"
        fake.write_text("not a database")
        import hashlib

        fake.with_suffix(".db.sha256").write_text(hashlib.sha256(fake.read_bytes()).hexdigest())
        with pytest.raises(backup.BackupError):
            backup.restore_backup(fake)

    def test_backup_is_a_valid_database(self, migrated_app):
        self.seed()
        path = backup.create_backup()
        with sqlite3.connect(path) as connection:
            assert connection.execute("SELECT count(*) FROM users").fetchone()[0] == 1
        connection.close()


def test_production_refuses_missing_secrets(monkeypatch):
    from app.config import ProductionConfig

    monkeypatch.setattr(ProductionConfig, "SECRET_KEY", None)
    with pytest.raises(RuntimeError, match="PTP_SECRET_KEY"):
        create_app("production")


def test_health_endpoints_reveal_nothing(client):
    assert client.get("/healthz").get_json() == {"status": "ok"}
