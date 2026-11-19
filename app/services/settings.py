"""Allow-listed, typed runtime settings stored in ``application_settings``."""
from __future__ import annotations

from dataclasses import dataclass

from app.extensions import db
from app.models import ApplicationSetting
from app.services import audit


@dataclass(frozen=True)
class SettingDefinition:
    key: str
    label: str
    help_text: str
    default: int
    minimum: int
    maximum: int


DEFINITIONS = {
    definition.key: definition
    for definition in (
        SettingDefinition(
            "auth.max_failed_logins",
            "Failed logins before lockout",
            "Consecutive failures that lock an account.",
            5, 3, 20,
        ),
        SettingDefinition(
            "auth.lockout_minutes",
            "Lockout duration (minutes)",
            "How long a locked account stays locked.",
            15, 1, 1440,
        ),
        SettingDefinition(
            "scope.min_ipv4_prefix",
            "Broadest IPv4 scope (CIDR prefix)",
            "Inclusions broader than this prefix are rejected.",
            16, 8, 32,
        ),
        SettingDefinition(
            "scope.min_ipv6_prefix",
            "Broadest IPv6 scope (CIDR prefix)",
            "Inclusions broader than this prefix are rejected.",
            48, 32, 128,
        ),
        SettingDefinition(
            "recon.rate_limit_rps",
            "Reconnaissance rate limit (requests/second)",
            "Upper limit passed to every reconnaissance tool.",
            10, 1, 100,
        ),
        SettingDefinition(
            "recon.tool_timeout_seconds",
            "Tool timeout (seconds)",
            "A tool still running after this long is stopped.",
            600, 30, 7200,
        ),
        SettingDefinition(
            "recon.max_hosts",
            "Maximum hosts per module",
            "Limits how many in-scope hosts one module will touch.",
            25, 1, 500,
        ),
        SettingDefinition(
            "recon.nmap_top_ports",
            "Ports scanned per host",
            "Number of most common TCP ports checked by Nmap.",
            100, 10, 1000,
        ),
        SettingDefinition(
            "mapping.max_depth",
            "Crawl depth limit",
            "How many links away from the starting pages the crawler may go.",
            3, 1, 10,
        ),
        SettingDefinition(
            "mapping.max_pages",
            "Crawl page limit",
            "Maximum requests the crawler sends in one job.",
            300, 10, 5000,
        ),
    )
}


def get_int(key: str) -> int:
    """Return a setting, falling back to its default if unset or out of range."""
    definition = DEFINITIONS[key]
    row = db.session.scalar(db.select(ApplicationSetting).filter_by(key=key))
    if row is None:
        return definition.default
    try:
        value = int(row.value)
    except ValueError:
        return definition.default
    return value if definition.minimum <= value <= definition.maximum else definition.default


def set_int(key: str, value: int, actor) -> None:
    """Validate and store a setting. The caller commits."""
    definition = DEFINITIONS.get(key)
    if definition is None:
        raise ValueError("Unknown setting.")
    if not definition.minimum <= value <= definition.maximum:
        raise ValueError(
            f"{definition.label} must be between {definition.minimum} and {definition.maximum}."
        )
    previous = get_int(key)
    if previous == value:
        return
    row = db.session.scalar(db.select(ApplicationSetting).filter_by(key=key))
    if row is None:
        row = ApplicationSetting(key=key, value=str(value), updated_by_id=actor.id)
        db.session.add(row)
    else:
        row.value = str(value)
        row.updated_by_id = actor.id
    audit.record(
        "settings.changed",
        object_type="setting",
        object_id=key,
        details={"from": previous, "to": value},
    )
