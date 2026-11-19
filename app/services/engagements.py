"""Engagement lifecycle, access control, authorization and the execution gate."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import date

from sqlalchemy import or_

from app.extensions import db
from app.models import (
    AuditOutcome,
    Engagement,
    EngagementScope,
    EngagementStatus,
    Target,
    User,
    engagement_testers,
    utcnow,
)
from app.models.base import TESTING_METHODS
from app.services import audit, settings
from app.services.scope import (
    Resolver,
    ScopeDecision,
    ScopeError,
    ScopeEvaluator,
    ScopeRule,
    normalize_rule,
    parse_target,
    sanitize_target,
)

ALLOWED_TRANSITIONS = {
    EngagementStatus.DRAFT: {EngagementStatus.ACTIVE, EngagementStatus.ARCHIVED},
    EngagementStatus.ACTIVE: {EngagementStatus.PAUSED, EngagementStatus.COMPLETED},
    EngagementStatus.PAUSED: {EngagementStatus.ACTIVE, EngagementStatus.COMPLETED},
    EngagementStatus.COMPLETED: {EngagementStatus.ARCHIVED},
    EngagementStatus.ARCHIVED: set(),
}
_CREDENTIAL_REFERENCE = re.compile(r"^(vault|env|keyring|op|bw|kp|ref)://[A-Za-z0-9._/-]{1,200}$")


class EngagementError(ValueError):
    """A user-correctable engagement problem."""


class ExecutionDenied(PermissionError):
    """Raised by the execution gate when testing must not proceed."""


@dataclass
class EngagementData:
    """Validated-by-form input for creating or updating an engagement."""

    name: str
    client_name: str
    primary_target_url: str
    start_date: date
    end_date: date
    description: str = ""
    rules_of_engagement: str = ""
    authorized_scope: list[str] = field(default_factory=list)
    excluded_scope: list[str] = field(default_factory=list)
    authorized_methods: list[str] = field(default_factory=list)
    credential_references: list[dict] = field(default_factory=list)
    tester_ids: list[int] = field(default_factory=list)


def parse_credential_references(text: str) -> list[dict]:
    """Parse ``label | scheme://path`` lines. Only references are stored, never secrets."""
    references = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        label, separator, reference = (part.strip() for part in line.partition("|"))
        if not separator or not label or not _CREDENTIAL_REFERENCE.match(reference):
            raise EngagementError(
                "Credential references must look like 'Admin account | vault://client/admin'. "
                "Store secrets in your vault, never here."
            )
        references.append({"label": label[:80], "reference": reference})
    return references


def visible_engagements_query(user: User):
    """Select the engagements ``user`` may see. All object-level access flows through this."""
    query = db.select(Engagement)
    if user.has_permission("engagement.view_all"):
        return query
    assigned = db.select(engagement_testers.c.engagement_id).where(
        engagement_testers.c.user_id == user.id
    )
    return query.where(or_(Engagement.created_by_id == user.id, Engagement.id.in_(assigned)))


def get_visible_engagement(user: User, engagement_id: int) -> Engagement | None:
    """Return the engagement if ``user`` may access it, otherwise ``None``."""
    query = visible_engagements_query(user).where(Engagement.id == engagement_id)
    return db.session.scalar(query)


def _build_rules(data: EngagementData) -> list[ScopeRule]:
    limits = {
        "min_ipv4_prefix": settings.get_int("scope.min_ipv4_prefix"),
        "min_ipv6_prefix": settings.get_int("scope.min_ipv6_prefix"),
    }
    rules: dict[tuple, ScopeRule] = {}
    try:
        for value in data.authorized_scope:
            rule = normalize_rule(value, **limits)
            rules[(rule.entry_type, rule.value, False)] = rule
        for value in data.excluded_scope:
            rule = normalize_rule(value, is_exclusion=True, **limits)
            rules[(rule.entry_type, rule.value, True)] = rule
    except ScopeError as exc:
        raise EngagementError(str(exc)) from exc
    if not any(not rule.is_exclusion for rule in rules.values()):
        raise EngagementError("At least one authorized domain or IP range is required.")
    return list(rules.values())


def _validate(data: EngagementData, rules: list[ScopeRule]) -> str:
    """Validate cross-field rules and return the canonical primary target host."""
    if data.end_date < data.start_date:
        raise EngagementError("The end date must not be before the start date.")
    unknown = set(data.authorized_methods) - set(TESTING_METHODS)
    if unknown:
        raise EngagementError("Unknown testing method selected.")
    try:
        parsed = parse_target(data.primary_target_url)
    except ScopeError as exc:
        raise EngagementError(f"Primary target: {exc}") from exc
    if parsed.scheme is None:
        raise EngagementError("The primary target must be a full http:// or https:// URL.")
    decision = ScopeEvaluator(rules).evaluate(data.primary_target_url)
    if not decision.allowed:
        raise EngagementError(f"The primary target is outside the scope: {decision.reason}")
    return parsed.host


def _resolve_testers(ids: list[int]) -> list[User]:
    if not ids:
        return []
    testers = list(db.session.scalars(db.select(User).where(User.id.in_(ids))))
    if len(testers) != len(set(ids)):
        raise EngagementError("An assigned tester does not exist.")
    return testers


def scope_fingerprint(engagement: Engagement) -> str:
    """Hash everything a client authorization covers."""
    material = {
        "rules": sorted(
            (entry.entry_type, entry.value, entry.is_exclusion)
            for entry in engagement.scope_entries
        ),
        "primary": engagement.primary_target_url,
        "start": engagement.start_date.isoformat(),
        "end": engagement.end_date.isoformat(),
        "methods": sorted(engagement.authorized_methods or []),
        "rules_of_engagement": engagement.rules_of_engagement,
    }
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()


def _sync_scope(engagement: Engagement, rules: list[ScopeRule]) -> None:
    wanted = {(rule.entry_type, rule.value, rule.is_exclusion) for rule in rules}
    for entry in list(engagement.scope_entries):
        if (entry.entry_type, entry.value, entry.is_exclusion) not in wanted:
            engagement.scope_entries.remove(entry)
    present = {
        (entry.entry_type, entry.value, entry.is_exclusion) for entry in engagement.scope_entries
    }
    for rule in rules:
        if (rule.entry_type, rule.value, rule.is_exclusion) not in present:
            engagement.scope_entries.append(
                EngagementScope(
                    entry_type=rule.entry_type, value=rule.value, is_exclusion=rule.is_exclusion
                )
            )


def _sync_primary_target(engagement: Engagement, url: str, host: str) -> None:
    for target in engagement.targets:
        target.is_primary = False
    existing = next((target for target in engagement.targets if target.url == url), None)
    if existing:
        existing.is_primary = True
        existing.host = host
    else:
        engagement.targets.append(Target(url=url, host=host, label="Primary", is_primary=True))


def _apply(engagement: Engagement, data: EngagementData, rules: list[ScopeRule], host: str) -> None:
    engagement.name = data.name.strip()
    engagement.client_name = data.client_name.strip()
    engagement.description = data.description.strip()
    engagement.primary_target_url = data.primary_target_url.strip()
    engagement.start_date = data.start_date
    engagement.end_date = data.end_date
    engagement.rules_of_engagement = data.rules_of_engagement.strip()
    engagement.authorized_methods = sorted(set(data.authorized_methods))
    engagement.credential_references = data.credential_references
    engagement.testers = _resolve_testers(data.tester_ids)
    _sync_scope(engagement, rules)
    _sync_primary_target(engagement, engagement.primary_target_url, host)


def create_engagement(data: EngagementData, actor: User) -> Engagement:
    """Create a draft engagement. The caller commits."""
    rules = _build_rules(data)
    host = _validate(data, rules)
    engagement = Engagement(created_by_id=actor.id, status=EngagementStatus.DRAFT)
    db.session.add(engagement)
    _apply(engagement, data, rules, host)
    db.session.flush()
    audit.record(
        "engagement.created",
        engagement_id=engagement.id,
        object_type="engagement",
        object_id=engagement.id,
        details={"name": engagement.name, "scope_rules": len(rules)},
    )
    return engagement


def update_engagement(engagement: Engagement, data: EngagementData, actor: User) -> bool:
    """Update an engagement. Returns True if a change revoked its authorization."""
    if engagement.status in (EngagementStatus.COMPLETED, EngagementStatus.ARCHIVED):
        raise EngagementError("Completed and archived engagements cannot be edited.")
    rules = _build_rules(data)
    host = _validate(data, rules)
    before = scope_fingerprint(engagement)
    _apply(engagement, data, rules, host)
    db.session.flush()
    revoked = False
    if engagement.is_authorized and scope_fingerprint(engagement) != before:
        _revoke_authorization(engagement, actor)
        revoked = True
    audit.record(
        "engagement.updated",
        engagement_id=engagement.id,
        object_type="engagement",
        object_id=engagement.id,
        details={"scope_changed": scope_fingerprint(engagement) != before},
    )
    return revoked


def _revoke_authorization(engagement: Engagement, actor: User) -> None:
    engagement.authorization_reference = None
    engagement.authorization_signatory = None
    engagement.authorization_confirmed_at = None
    engagement.authorization_confirmed_by_id = None
    engagement.authorized_scope_fingerprint = None
    if engagement.status in (EngagementStatus.ACTIVE, EngagementStatus.PAUSED):
        engagement.status = EngagementStatus.DRAFT
    audit.record(
        "engagement.authorization_revoked",
        engagement_id=engagement.id,
        object_type="engagement",
        object_id=engagement.id,
        details={"reason": "authorized_scope_changed"},
        actor=actor,
    )


def confirm_authorization(
    engagement: Engagement, actor: User, reference: str, signatory: str
) -> None:
    """Record the client's written authorization, pinned to the current scope."""
    if engagement.status != EngagementStatus.DRAFT:
        raise EngagementError("Authorization is recorded while the engagement is a draft.")
    if not reference.strip() or not signatory.strip():
        raise EngagementError("The authorization reference and signatory are both required.")
    if not engagement.authorized_methods:
        raise EngagementError("Select at least one authorized testing method first.")
    engagement.authorization_reference = reference.strip()
    engagement.authorization_signatory = signatory.strip()
    engagement.authorization_confirmed_at = utcnow()
    engagement.authorization_confirmed_by_id = actor.id
    engagement.authorized_scope_fingerprint = scope_fingerprint(engagement)
    audit.record(
        "engagement.authorized",
        engagement_id=engagement.id,
        object_type="engagement",
        object_id=engagement.id,
        details={
            "reference": engagement.authorization_reference,
            "signatory": engagement.authorization_signatory,
            "scope_fingerprint": engagement.authorized_scope_fingerprint,
        },
    )


def authorization_is_current(engagement: Engagement) -> bool:
    """True when an authorization exists and still covers the stored scope."""
    return (
        engagement.is_authorized
        and engagement.authorized_scope_fingerprint == scope_fingerprint(engagement)
    )


def transition(engagement: Engagement, new_status: str, actor: User) -> None:
    """Move an engagement through its lifecycle. The caller commits."""
    if new_status not in ALLOWED_TRANSITIONS.get(engagement.status, set()):
        raise EngagementError(f"Cannot move from {engagement.status} to {new_status}.")
    if new_status == EngagementStatus.ACTIVE:
        if not authorization_is_current(engagement):
            raise EngagementError("Record current client authorization before starting.")
        if utcnow().date() > engagement.end_date:
            raise EngagementError("The testing window has already ended.")
    previous = engagement.status
    engagement.status = new_status
    audit.record(
        "engagement.status_changed",
        engagement_id=engagement.id,
        object_type="engagement",
        object_id=engagement.id,
        details={"from": previous, "to": new_status},
        actor=actor,
    )


def build_evaluator(engagement: Engagement, resolver: Resolver | None = None) -> ScopeEvaluator:
    """Build a scope evaluator from an engagement's stored rules."""
    rules = [
        ScopeRule(entry.entry_type, entry.value, entry.is_exclusion)
        for entry in engagement.scope_entries
    ]
    return ScopeEvaluator(rules, resolver=resolver)


def check_target(
    engagement: Engagement, target: str, actor: User, *, resolve: bool = False,
    resolver: Resolver | None = None,
) -> ScopeDecision:
    """Evaluate a target against scope and audit the decision. The caller commits."""
    decision = build_evaluator(engagement, resolver).evaluate(target, resolve=resolve)
    audit.record(
        "scope.check",
        outcome=AuditOutcome.SUCCESS if decision.allowed else AuditOutcome.DENIED,
        engagement_id=engagement.id,
        object_type="target",
        details=decision.as_dict() | {"target": sanitize_target(target)},
        actor=actor,
    )
    return decision


def execution_precondition_failure(engagement: Engagement, actor: User, method: str) -> str | None:
    """Return why testing may not proceed on this engagement, or ``None`` if it may."""
    if not actor.has_permission("assessment.execute"):
        return "You do not have permission to execute assessments."
    if get_visible_engagement(actor, engagement.id) is None:
        return "You are not assigned to this engagement."
    if engagement.status != EngagementStatus.ACTIVE:
        return f"The engagement is {engagement.status}, not active."
    if not authorization_is_current(engagement):
        return "Client authorization is missing or does not cover the current scope."
    if not engagement.within_window():
        return "The current date is outside the authorized testing window."
    if method not in (engagement.authorized_methods or []):
        return f"The testing method '{method}' is not authorized for this engagement."
    return None


def authorize_passive_enumeration(
    engagement: Engagement, domain: str, actor: User, method: str
) -> None:
    """Gate third-party subdomain enumeration of a domain covered by a wildcard rule.

    The target itself receives no traffic, but the domain must still be explicitly authorized.
    """
    failure = execution_precondition_failure(engagement, actor, method)
    if failure is None:
        wildcard = f"*.{domain}"
        covered = any(entry.value == wildcard for entry in engagement.inclusions)
        probe = build_evaluator(engagement).evaluate(f"ptp-scope-probe.{domain}")
        excluded = any(
            entry.entry_type == "domain" and domain == entry.value for entry in engagement.exclusions
        )
        if not covered or not probe.allowed or excluded:
            failure = f"{domain} is not covered by an authorized wildcard rule."
    audit.record(
        "execution.gate",
        outcome=AuditOutcome.DENIED if failure else AuditOutcome.SUCCESS,
        engagement_id=engagement.id,
        object_type="domain",
        details={"method": method, "target": domain, "passive": True, "failure": failure},
        actor=actor,
    )
    db.session.commit()
    if failure:
        raise ExecutionDenied(failure)


def authorize_execution(
    engagement: Engagement, target: str, actor: User, method: str,
    *, resolver: Resolver | None = None,
) -> ScopeDecision:
    """The mandatory gate every testing action must pass before touching a target.

    Commits the audit record and raises :class:`ExecutionDenied` when any check fails.
    """
    failure = execution_precondition_failure(engagement, actor, method)

    if failure is None:
        decision = build_evaluator(engagement, resolver).evaluate(target, resolve=True)
        if not decision.allowed:
            failure = decision.reason
    else:
        decision = ScopeDecision(False, str(target)[:255], failure)

    audit.record(
        "execution.gate",
        outcome=AuditOutcome.DENIED if failure else AuditOutcome.SUCCESS,
        engagement_id=engagement.id,
        object_type="target",
        details={
            "method": method,
            **decision.as_dict(),
            "target": sanitize_target(target),
            "failure": failure,
        },
        actor=actor,
    )
    db.session.commit()
    if failure:
        raise ExecutionDenied(failure)
    return decision
