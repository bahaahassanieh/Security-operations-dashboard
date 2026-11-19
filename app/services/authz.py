"""Role-based access control: the permission catalogue, seeding and route decorators."""
from __future__ import annotations

from functools import wraps

from flask import abort
from flask_login import current_user, login_required

from app.extensions import db
from app.models import AuditOutcome, Permission, Role
from app.services import audit

PERMISSIONS = {
    "engagement.view": ("engagement", "View assigned engagements"),
    "engagement.view_all": ("engagement", "View every engagement"),
    "engagement.create": ("engagement", "Create engagements"),
    "engagement.edit": ("engagement", "Edit engagements and their scope"),
    "engagement.authorize": ("engagement", "Record client authorization for testing"),
    "engagement.manage_status": ("engagement", "Start, pause, complete and archive engagements"),
    "scope.check": ("engagement", "Run scope checks against an engagement"),
    "assessment.execute": ("testing", "Execute assessments and security tools"),
    "findings.view": ("findings", "View findings"),
    "findings.manage": ("findings", "Create and edit findings"),
    "findings.validate": ("findings", "Confirm or reject findings"),
    "evidence.view": ("findings", "View evidence"),
    "evidence.manage": ("findings", "Add and remove evidence"),
    "reports.view": ("reports", "View reports"),
    "reports.generate": ("reports", "Generate reports"),
    "tools.manage": ("system", "Manage the security tool registry"),
    "users.manage": ("system", "Manage users and roles"),
    "settings.manage": ("system", "Change system settings"),
    "audit.view": ("system", "View and verify the audit log"),
}

ROLE_DEFAULTS = {
    "Administrator": ("Full platform administration.", set(PERMISSIONS), True),
    "Lead Tester": (
        "Runs engagements, records authorization and validates findings.",
        set(PERMISSIONS) - {"users.manage", "settings.manage", "tools.manage"},
        False,
    ),
    "Penetration Tester": (
        "Performs testing on assigned engagements.",
        {
            "engagement.view",
            "scope.check",
            "assessment.execute",
            "findings.view",
            "findings.manage",
            "findings.validate",
            "evidence.view",
            "evidence.manage",
            "reports.view",
            "reports.generate",
        },
        False,
    ),
    "Auditor": (
        "Read-only oversight of all engagements and the audit log.",
        {
            "engagement.view",
            "engagement.view_all",
            "findings.view",
            "evidence.view",
            "reports.view",
            "audit.view",
        },
        False,
    ),
    "Client Viewer": (
        "Read-only access to assigned engagements.",
        {"engagement.view", "findings.view", "reports.view"},
        False,
    ),
}


def seed_rbac() -> None:
    """Create missing permissions and roles. Existing customizations are left untouched."""
    existing = {permission.code: permission for permission in db.session.scalars(db.select(Permission))}
    for code, (category, description) in PERMISSIONS.items():
        if code not in existing:
            existing[code] = Permission(code=code, category=category, description=description)
            db.session.add(existing[code])

    roles = {role.name: role for role in db.session.scalars(db.select(Role))}
    for name, (description, codes, locked) in ROLE_DEFAULTS.items():
        if name not in roles:
            db.session.add(
                Role(
                    name=name,
                    description=description,
                    is_locked=locked,
                    permissions=[existing[code] for code in sorted(codes)],
                )
            )
    # The locked administrator role always holds every permission, including new ones.
    administrator = roles.get("Administrator")
    if administrator is not None:
        administrator.permissions = list(existing.values())
    db.session.commit()


def permission_required(*codes: str):
    """Require an authenticated user holding all of ``codes``. Denials are audited."""

    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            missing = [code for code in codes if not current_user.has_permission(code)]
            if missing:
                audit.record(
                    "authz.denied",
                    outcome=AuditOutcome.DENIED,
                    object_type="permission",
                    details={"required": missing, "view": view.__name__},
                )
                db.session.commit()
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator
