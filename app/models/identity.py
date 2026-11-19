"""Users, roles and permissions."""
from __future__ import annotations

import secrets

from flask_login import UserMixin

from app.extensions import db
from app.models.base import TimestampMixin, utcnow

role_permissions = db.Table(
    "role_permissions",
    db.Column(
        "role_id", db.Integer, db.ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    ),
    db.Column(
        "permission_id",
        db.Integer,
        db.ForeignKey("permissions.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


def new_session_token() -> str:
    """Generate the per-user token that invalidates sessions when rotated."""
    return secrets.token_urlsafe(32)


class Permission(db.Model):
    """A single grantable capability, e.g. ``engagement.create``."""

    __tablename__ = "permissions"

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(64), nullable=False, unique=True)
    category = db.Column(db.String(32), nullable=False, index=True)
    description = db.Column(db.String(255), nullable=False)


class Role(TimestampMixin, db.Model):
    """A named set of permissions."""

    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False, unique=True)
    description = db.Column(db.String(255), nullable=False, default="")
    is_locked = db.Column(db.Boolean, nullable=False, default=False)

    permissions = db.relationship("Permission", secondary=role_permissions, lazy="selectin")
    users = db.relationship("User", back_populates="role")

    def permission_codes(self) -> set[str]:
        return {permission.code for permission in self.permissions}


class User(UserMixin, TimestampMixin, db.Model):
    """A platform account. Accounts are disabled rather than deleted to preserve the audit trail."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False, unique=True)
    email = db.Column(db.String(255), nullable=False, unique=True)
    full_name = db.Column(db.String(128), nullable=False, default="")
    password_hash = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False, index=True)

    is_enabled = db.Column(db.Boolean, nullable=False, default=True)
    must_change_password = db.Column(db.Boolean, nullable=False, default=True)
    session_token = db.Column(db.String(64), nullable=False, default=new_session_token)
    failed_login_count = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime)
    last_login_at = db.Column(db.DateTime)
    last_login_ip = db.Column(db.String(45))
    password_changed_at = db.Column(db.DateTime)

    role = db.relationship("Role", back_populates="users", lazy="joined")

    @property
    def is_active(self) -> bool:  # Flask-Login contract
        return self.is_enabled

    @property
    def is_locked(self) -> bool:
        return self.locked_until is not None and self.locked_until > utcnow()

    @property
    def display_name(self) -> str:
        return self.full_name or self.username

    def get_id(self) -> str:
        """Bind the session to the rotating token so it can be revoked server-side."""
        return f"{self.id}:{self.session_token}"

    def has_permission(self, code: str) -> bool:
        return self.is_enabled and code in self.role.permission_codes()

    def rotate_session_token(self) -> None:
        """Invalidate every existing session for this user."""
        self.session_token = new_session_token()
