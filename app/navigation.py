"""Sidebar definition. Items from later phases are shown as unavailable, never as working pages."""
from __future__ import annotations

from dataclasses import dataclass

from flask import url_for


@dataclass(frozen=True)
class NavItem:
    label: str
    icon: str
    endpoint: str | None = None
    prefix: str | None = None
    permission: str | None = None
    phase: int | None = None


NAV_ITEMS = (
    NavItem("Dashboard", "speedometer2", "dashboard.index", "dashboard."),
    NavItem("Engagements", "briefcase", "engagements.index", "engagements.", "engagement.view"),
    NavItem("Targets & Assets", "hdd-network", "assets.index", "assets.", "engagement.view"),
    NavItem("Reconnaissance", "binoculars", "recon.index", "recon.", "engagement.view"),
    NavItem("Application Mapping", "diagram-3", "mapping.index", "mapping.", "engagement.view"),
    NavItem("Vulnerability Scanner", "radar", "findings.imports", "findings.import", "findings.view"),
    NavItem("Testing Methodology", "journal-check", "methodology.progress", "methodology.progress", "engagement.view"),
    NavItem("Test Case Library", "collection", "methodology.library", "methodology.library", "engagement.view"),
    NavItem("API Testing", "braces", "apitest.index", "apitest.", "engagement.view"),
    NavItem("Manual Testing", "person-check", "manual.index", "manual.", "engagement.view"),
    NavItem("Findings", "bug", "findings.finding_list", "findings.finding", "findings.view"),
    NavItem("Evidence", "archive", "evidence.index", "evidence.", "evidence.view"),
    NavItem("Reports", "file-earmark-text", "reports.index", "reports.", "reports.view"),
    NavItem("Retesting", "arrow-repeat", "retesting.index", "retesting.", "findings.view"),
    NavItem("Tool Management", "tools", "tools.index", "tools.", "engagement.view"),
    NavItem("System Settings", "gear", "admin.settings", "admin.", "settings.manage"),
    NavItem("Audit Logs", "shield-check", "audit.index", "audit.", "audit.view"),
)


def build_navigation(user, active_endpoint: str | None) -> list[dict]:
    """Return the sidebar entries visible to ``user``."""
    if not user.is_authenticated:
        return []
    items = []
    for item in NAV_ITEMS:
        endpoint = item.endpoint
        if item.permission and not user.has_permission(item.permission):
            if endpoint != "admin.settings" or not user.has_permission("users.manage"):
                continue
            endpoint = "admin.users"  # User managers without settings access land on Users.
        items.append(
            {
                "label": item.label,
                "icon": item.icon,
                "url": url_for(endpoint) if endpoint else None,
                "active": bool(item.prefix and (active_endpoint or "").startswith(item.prefix)),
                "phase": item.phase,
            }
        )
    return items
