"""Account lifecycle: password hashing, authentication, lockout and administration."""
from __future__ import annotations

import re
import secrets
from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from flask import current_app, request

from app.extensions import db
from app.models import AuditOutcome, Role, User, utcnow
from app.services import audit, settings

_hasher = PasswordHasher()
# Verified for unknown usernames so response time does not reveal which accounts exist.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9._-]{3,64}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}$")
ADMIN_PERMISSION = "users.manage"


class AccountError(ValueError):
    """A user-correctable account problem."""


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def validate_password_strength(password: str, username: str = "") -> None:
    """Enforce the password policy, raising :class:`AccountError` on failure."""
    minimum = current_app.config["PASSWORD_MIN_LENGTH"]
    if len(password) < minimum:
        raise AccountError(f"Password must be at least {minimum} characters long.")
    if len(password) > 256:
        raise AccountError("Password must be at most 256 characters long.")
    classes = sum(
        bool(re.search(pattern, password))
        for pattern in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^a-zA-Z0-9]")
    )
    if classes < 3:
        raise AccountError(
            "Password must mix at least three of: lowercase, uppercase, digits, symbols."
        )
    if username and username.lower() in password.lower():
        raise AccountError("Password must not contain the username.")


def generate_temporary_password() -> str:
    """Create a policy-compliant one-time password."""
    return f"Tmp-{secrets.token_urlsafe(18)}-9a"


def authenticate(username: str, password: str) -> User | None:
    """Verify credentials, applying lockout and auditing every attempt. Commits."""
    user = db.session.scalar(db.select(User).filter_by(username=username.strip()))
    if user is None:
        verify_password(_DUMMY_HASH, password)
        audit.record(
            "auth.login",
            outcome=AuditOutcome.FAILURE,
            actor_name="anonymous",
            # Anything unlike a username may be a password typed into the wrong field.
            details={
                "reason": "unknown_user",
                "username": username if USERNAME_PATTERN.match(username) else "[invalid-format]",
            },
        )
        db.session.commit()
        return None

    password_valid = verify_password(user.password_hash, password)

    if not user.is_enabled or user.is_locked:
        reason = "disabled" if not user.is_enabled else "locked"
        audit.record(
            "auth.login",
            outcome=AuditOutcome.DENIED,
            actor_name=user.username,
            object_type="user",
            object_id=user.id,
            details={"reason": reason},
        )
        db.session.commit()
        return None

    if not password_valid:
        user.failed_login_count += 1
        details = {"reason": "bad_password", "failures": user.failed_login_count}
        if user.failed_login_count >= settings.get_int("auth.max_failed_logins"):
            user.locked_until = utcnow() + timedelta(
                minutes=settings.get_int("auth.lockout_minutes")
            )
            user.failed_login_count = 0
            details["locked_until"] = user.locked_until.isoformat()
        audit.record(
            "auth.login",
            outcome=AuditOutcome.FAILURE,
            actor_name=user.username,
            object_type="user",
            object_id=user.id,
            details=details,
        )
        db.session.commit()
        return None

    if _hasher.check_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = utcnow()
    user.last_login_ip = request.remote_addr
    audit.record("auth.login", actor=user, object_type="user", object_id=user.id)
    db.session.commit()
    return user


def change_password(user: User, current_password: str, new_password: str) -> None:
    """Change a user's own password and revoke their other sessions. The caller commits."""
    if not verify_password(user.password_hash, current_password):
        raise AccountError("Current password is incorrect.")
    validate_password_strength(new_password, user.username)
    if verify_password(user.password_hash, new_password):
        raise AccountError("New password must differ from the current password.")
    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    user.password_changed_at = utcnow()
    user.rotate_session_token()
    audit.record("auth.password_changed", actor=user, object_type="user", object_id=user.id)


def _enabled_admin_count() -> int:
    users = db.session.scalars(db.select(User).filter_by(is_enabled=True))
    return sum(1 for user in users if user.has_permission(ADMIN_PERMISSION))


def _validate_identity(username: str, email: str, exclude_id: int | None = None) -> None:
    if not USERNAME_PATTERN.match(username):
        raise AccountError("Username must be 3-64 letters, digits, dots, dashes or underscores.")
    if not EMAIL_PATTERN.match(email):
        raise AccountError("Enter a valid email address.")
    query = db.select(User).where((User.username == username) | (User.email == email))
    clash = db.session.scalar(query)
    if clash is not None and clash.id != exclude_id:
        raise AccountError("That username or email is already in use.")


def create_user(
    username: str, email: str, full_name: str, role: Role, password: str | None = None,
    *, must_change_password: bool = True,
) -> tuple[User, str]:
    """Create an account and return it with its initial password. The caller commits."""
    username, email = username.strip(), email.strip().lower()
    _validate_identity(username, email)
    initial_password = password or generate_temporary_password()
    validate_password_strength(initial_password, username)
    user = User(
        username=username,
        email=email,
        full_name=full_name.strip(),
        role=role,
        password_hash=hash_password(initial_password),
        must_change_password=must_change_password,
    )
    db.session.add(user)
    db.session.flush()
    audit.record(
        "user.created",
        object_type="user",
        object_id=user.id,
        details={"username": username, "role": role.name},
    )
    return user, initial_password


def update_user(user: User, actor: User, *, email: str, full_name: str, role: Role, enabled: bool) -> None:
    """Update an account, protecting the last administrator. The caller commits."""
    email = email.strip().lower()
    _validate_identity(user.username, email, exclude_id=user.id)
    if user.id == actor.id and (not enabled or role.id != user.role_id):
        raise AccountError("You cannot disable your own account or change your own role.")

    loses_admin = user.has_permission(ADMIN_PERMISSION) and (
        not enabled or ADMIN_PERMISSION not in role.permission_codes()
    )
    if loses_admin and _enabled_admin_count() <= 1:
        raise AccountError("This is the last active administrator.")

    changes = {}
    if user.email != email:
        changes["email"] = email
    if user.full_name != full_name.strip():
        changes["full_name"] = full_name.strip()
    if user.role_id != role.id:
        changes["role"] = {"from": user.role.name, "to": role.name}
    if user.is_enabled != enabled:
        changes["enabled"] = enabled

    user.email = email
    user.full_name = full_name.strip()
    user.role = role
    user.is_enabled = enabled
    if "role" in changes or "enabled" in changes:
        user.rotate_session_token()
    if changes:
        audit.record("user.updated", object_type="user", object_id=user.id, details=changes)


def reset_password(user: User) -> str:
    """Issue a one-time password, unlock the account and revoke sessions. The caller commits."""
    temporary = generate_temporary_password()
    user.password_hash = hash_password(temporary)
    user.must_change_password = True
    user.failed_login_count = 0
    user.locked_until = None
    user.rotate_session_token()
    audit.record("user.password_reset", object_type="user", object_id=user.id)
    return temporary
