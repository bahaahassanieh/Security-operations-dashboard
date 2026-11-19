"""Engagement lifecycle, authorization and the execution gate."""
from __future__ import annotations

from datetime import date, timedelta

import pytest

from app.extensions import db
from app.models import ActivityLog, EngagementStatus
from app.services import engagements as service
from tests.conftest import engagement_data

PUBLIC = lambda _host: ["93.184.216.34"]  # noqa: E731


def form_payload(**overrides):
    today = date.today()
    payload = {
        "name": "Web App Test",
        "client_name": "Contoso",
        "primary_target_url": "https://app.contoso-lab.test/",
        "start_date": today.isoformat(),
        "end_date": (today + timedelta(days=5)).isoformat(),
        "authorized_scope": "app.contoso-lab.test\n198.51.100.0/24",
        "excluded_scope": "198.51.100.7",
        "authorized_methods": ["manual_testing"],
        "credential_references": "Standard user | vault://contoso/user",
    }
    payload.update(overrides)
    return payload


class TestCreation:
    def test_create_through_ui(self, client, login, lead):
        login("lead.tester")
        response = client.post("/engagements/new", data=form_payload())
        assert response.status_code == 302
        item = db.session.scalar(service.visible_engagements_query(lead))
        assert item.status == EngagementStatus.DRAFT
        assert {entry.value for entry in item.inclusions} == {
            "app.contoso-lab.test", "198.51.100.0/24",
        }
        assert item.targets[0].is_primary and item.targets[0].host == "app.contoso-lab.test"

    def test_primary_target_outside_scope_is_rejected(self, client, login, lead):
        login("lead.tester")
        response = client.post(
            "/engagements/new", data=form_payload(primary_target_url="https://evil.test/")
        )
        assert response.status_code == 200 and b"outside the scope" in response.data
        assert db.session.scalar(service.visible_engagements_query(lead)) is None

    def test_excluded_primary_target_is_rejected(self, lead):
        with pytest.raises(service.EngagementError):
            service.create_engagement(
                engagement_data(excluded_scope=["app.acme-corp.test"]), lead
            )

    @pytest.mark.parametrize("scope", ["*.com", "0.0.0.0/0", "10.0.0.0/8"])
    def test_broad_scope_is_rejected(self, client, login, lead, scope):
        login("lead.tester")
        response = client.post("/engagements/new", data=form_payload(authorized_scope=scope))
        assert response.status_code == 200
        assert db.session.scalar(service.visible_engagements_query(lead)) is None

    def test_end_before_start_is_rejected(self, lead):
        today = date.today()
        with pytest.raises(service.EngagementError):
            service.create_engagement(
                engagement_data(start_date=today, end_date=today - timedelta(days=1)), lead
            )

    @pytest.mark.parametrize(
        "line", ["admin | hunter2", "admin:password", "admin | https://x/y", "| vault://a"]
    )
    def test_plaintext_credentials_are_rejected(self, line):
        with pytest.raises(service.EngagementError):
            service.parse_credential_references(line)


class TestAuthorization:
    def test_cannot_start_without_authorization(self, engagement, lead):
        with pytest.raises(service.EngagementError, match="authorization"):
            service.transition(engagement, EngagementStatus.ACTIVE, lead)

    def test_authorization_requires_confirmation_tick(self, client, login, engagement):
        login("lead.tester")
        client.post(
            f"/engagements/{engagement.id}/authorize",
            data={"authorization_reference": "SOW-9", "authorization_signatory": "CISO"},
        )
        db.session.refresh(engagement)
        assert not engagement.is_authorized

    def test_full_authorization_flow(self, client, login, engagement):
        login("lead.tester")
        client.post(
            f"/engagements/{engagement.id}/authorize",
            data={
                "authorization_reference": "SOW-9",
                "authorization_signatory": "CISO",
                "confirm": "y",
            },
        )
        client.post(f"/engagements/{engagement.id}/status", data={"status": "active"})
        db.session.refresh(engagement)
        assert engagement.status == EngagementStatus.ACTIVE
        assert service.authorization_is_current(engagement)

    @pytest.mark.parametrize(
        "change",
        [
            {"authorized_scope": ["app.acme-corp.test", "new.acme-corp.test"]},
            {"excluded_scope": []},
            {"end_date": date.today() + timedelta(days=30)},
            {"authorized_methods": ["active_recon", "exploit_validation"]},
            {"rules_of_engagement": "Anything goes."},
        ],
    )
    def test_scope_change_revokes_authorization(self, active_engagement, lead, change):
        revoked = service.update_engagement(active_engagement, engagement_data(**change), lead)
        db.session.commit()
        assert revoked and not active_engagement.is_authorized
        assert active_engagement.status == EngagementStatus.DRAFT

    def test_cosmetic_change_keeps_authorization(self, active_engagement, lead):
        revoked = service.update_engagement(
            active_engagement, engagement_data(description="Updated notes"), lead
        )
        assert not revoked and service.authorization_is_current(active_engagement)

    @pytest.mark.parametrize(
        "start,end",
        [("draft", "completed"), ("draft", "paused"), ("archived", "active"), ("completed", "active")],
    )
    def test_invalid_transitions_are_rejected(self, engagement, lead, start, end):
        engagement.status = start
        with pytest.raises(service.EngagementError):
            service.transition(engagement, end, lead)


class TestExecutionGate:
    """Every condition must hold before a target may be touched."""

    @pytest.fixture
    def tester(self, make_user, active_engagement):
        user = make_user("gate.tester")
        active_engagement.testers.append(user)
        db.session.commit()
        return user

    def gate(self, engagement, user, target="https://app.acme-corp.test/", method="active_recon"):
        return service.authorize_execution(engagement, target, user, method, resolver=PUBLIC)

    def test_allows_when_everything_is_valid(self, active_engagement, tester):
        assert self.gate(active_engagement, tester).allowed

    def test_out_of_scope_target_is_denied_and_audited(self, active_engagement, tester):
        with pytest.raises(service.ExecutionDenied):
            self.gate(active_engagement, tester, target="https://evil.test/")
        entry = db.session.scalar(
            db.select(ActivityLog).filter_by(action="execution.gate", outcome="denied")
        )
        assert entry is not None and "evil.test" in entry.details

    def test_excluded_target_is_denied(self, active_engagement, tester):
        with pytest.raises(service.ExecutionDenied):
            self.gate(active_engagement, tester, target="pay.staging.acme-corp.test")

    def test_draft_engagement_is_denied(self, engagement, make_user):
        tester = make_user("draft.tester")
        engagement.testers.append(tester)
        with pytest.raises(service.ExecutionDenied, match="not active"):
            self.gate(engagement, tester)

    @pytest.mark.parametrize("status", ["paused", "completed", "archived"])
    def test_inactive_statuses_are_denied(self, active_engagement, tester, status):
        active_engagement.status = status
        with pytest.raises(service.ExecutionDenied):
            self.gate(active_engagement, tester)

    def test_expired_window_is_denied(self, active_engagement, tester):
        today = date.today()
        active_engagement.start_date = today - timedelta(days=9)
        active_engagement.end_date = today - timedelta(days=2)
        active_engagement.authorized_scope_fingerprint = service.scope_fingerprint(active_engagement)
        with pytest.raises(service.ExecutionDenied, match="window"):
            self.gate(active_engagement, tester)

    def test_future_window_is_denied(self, active_engagement, tester):
        today = date.today()
        active_engagement.start_date = today + timedelta(days=2)
        active_engagement.end_date = today + timedelta(days=9)
        active_engagement.authorized_scope_fingerprint = service.scope_fingerprint(active_engagement)
        with pytest.raises(service.ExecutionDenied, match="window"):
            self.gate(active_engagement, tester)

    def test_direct_database_scope_tampering_is_denied(self, active_engagement, tester):
        active_engagement.scope_entries[0].value = "evil.test"
        db.session.flush()
        with pytest.raises(service.ExecutionDenied, match="authorization"):
            self.gate(active_engagement, tester, target="evil.test")

    def test_unauthorized_method_is_denied(self, active_engagement, tester):
        with pytest.raises(service.ExecutionDenied, match="method"):
            self.gate(active_engagement, tester, method="exploit_validation")

    def test_unassigned_tester_is_denied(self, active_engagement, make_user):
        with pytest.raises(service.ExecutionDenied, match="assigned"):
            self.gate(active_engagement, make_user("stranger"))

    def test_role_without_execute_permission_is_denied(self, active_engagement, make_user):
        viewer = make_user("client.view", "Client Viewer")
        active_engagement.testers.append(viewer)
        with pytest.raises(service.ExecutionDenied, match="permission"):
            self.gate(active_engagement, viewer)

    def test_dns_rebinding_is_denied(self, active_engagement, tester):
        with pytest.raises(service.ExecutionDenied):
            service.authorize_execution(
                active_engagement, "app.acme-corp.test", tester, "active_recon",
                resolver=lambda _host: ["127.0.0.1"],
            )


class TestScopeCheckEndpoints:
    def test_ui_check_shows_decision_and_audits(self, client, login, engagement):
        login("lead.tester")
        response = client.post(
            f"/engagements/{engagement.id}/scope-check", data={"target": "https://evil.test/"}
        )
        assert b"Denied" in response.data
        assert db.session.scalar(db.select(ActivityLog).filter_by(action="scope.check")) is not None

    def test_api_check(self, client, login, engagement):
        login("lead.tester")
        url = f"/api/v1/engagements/{engagement.id}/scope-check"
        assert client.post(url, json={"target": "app.acme-corp.test"}).get_json()["allowed"] is True
        assert client.post(url, json={"target": "evil.test"}).get_json()["allowed"] is False
        assert client.post(url, json={"target": 42}).status_code == 400
