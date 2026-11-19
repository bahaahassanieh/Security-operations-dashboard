"""System settings, user administration and role management."""
from __future__ import annotations

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user
from flask_wtf import FlaskForm
from wtforms import BooleanField, EmailField, SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Length, Optional

from app.extensions import db
from app.models import Permission, Role, User
from app.services import accounts, audit, settings
from app.services.authz import permission_required

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


class UserForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=64)])
    email = EmailField("Email", validators=[DataRequired(), Length(max=255)])
    full_name = StringField("Full name", validators=[Optional(), Length(max=128)])
    role_id = SelectField("Role", coerce=int)
    is_enabled = BooleanField("Account enabled", default=True)
    submit = SubmitField("Save user")


class ActionForm(FlaskForm):
    """An empty form that carries the CSRF token for button-only actions."""


def _role_choices() -> list[tuple[int, str]]:
    return [(role.id, role.name) for role in db.session.scalars(db.select(Role).order_by(Role.name))]


def _get_or_404(model, object_id: int):
    instance = db.session.get(model, object_id)
    if instance is None:
        abort(404)
    return instance


@admin_bp.route("/settings", endpoint="settings", methods=["GET", "POST"])
@permission_required("settings.manage")
def settings_page():
    form = ActionForm()
    if form.validate_on_submit():
        try:
            for key in settings.DEFINITIONS:
                raw = request.form.get(key, "")
                if not raw.lstrip("-").isdigit():
                    raise ValueError(f"{settings.DEFINITIONS[key].label} must be a whole number.")
                settings.set_int(key, int(raw), current_user)
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            db.session.commit()
            flash("Settings saved.", "success")
            return redirect(url_for("admin.settings"))
    values = [(definition, settings.get_int(key)) for key, definition in settings.DEFINITIONS.items()]
    return render_template("admin/settings.html", form=form, values=values)


@admin_bp.route("/users")
@permission_required("users.manage")
def users():
    page = db.paginate(db.select(User).order_by(User.username), per_page=25, error_out=False)
    return render_template("admin/users.html", page=page, action_form=ActionForm())


@admin_bp.route("/users/new", methods=["GET", "POST"])
@permission_required("users.manage")
def create_user():
    form = UserForm()
    form.role_id.choices = _role_choices()
    if form.validate_on_submit():
        role = _get_or_404(Role, form.role_id.data)
        try:
            user, password = accounts.create_user(
                form.username.data, form.email.data, form.full_name.data or "", role
            )
        except accounts.AccountError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            db.session.commit()
            return render_template("admin/temporary_password.html", user=user, password=password)
    return render_template("admin/user_form.html", form=form, user=None)


@admin_bp.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@permission_required("users.manage")
def edit_user(user_id: int):
    user = _get_or_404(User, user_id)
    form = UserForm(obj=user)
    form.role_id.choices = _role_choices()
    form.username.data = user.username  # Usernames are immutable for audit continuity.
    if form.validate_on_submit():
        role = _get_or_404(Role, form.role_id.data)
        try:
            accounts.update_user(
                user,
                current_user,
                email=form.email.data,
                full_name=form.full_name.data or "",
                role=role,
                enabled=form.is_enabled.data,
            )
        except accounts.AccountError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            db.session.commit()
            flash("User updated.", "success")
            return redirect(url_for("admin.users"))
    return render_template("admin/user_form.html", form=form, user=user)


@admin_bp.route("/users/<int:user_id>/reset-password", methods=["POST"])
@permission_required("users.manage")
def reset_password(user_id: int):
    user = _get_or_404(User, user_id)
    form = ActionForm()
    if not form.validate_on_submit():
        abort(400)
    if user.id == current_user.id:
        flash("Use the change password page for your own account.", "warning")
        return redirect(url_for("admin.users"))
    password = accounts.reset_password(user)
    db.session.commit()
    return render_template("admin/temporary_password.html", user=user, password=password)


@admin_bp.route("/roles", methods=["GET", "POST"])
@permission_required("users.manage")
def roles():
    form = ActionForm()
    all_roles = db.session.scalars(db.select(Role).order_by(Role.id)).all()
    permissions = db.session.scalars(
        db.select(Permission).order_by(Permission.category, Permission.code)
    ).all()
    if form.validate_on_submit():
        by_id = {permission.id: permission for permission in permissions}
        for role in all_roles:
            if role.is_locked:
                continue
            selected = {
                by_id[int(value)]
                for value in request.form.getlist(f"role-{role.id}")
                if value.isdigit() and int(value) in by_id
            }
            before, after = role.permission_codes(), {item.code for item in selected}
            if before != after:
                role.permissions = sorted(selected, key=lambda item: item.id)
                audit.record(
                    "role.permissions_changed",
                    object_type="role",
                    object_id=role.id,
                    details={
                        "role": role.name,
                        "granted": sorted(after - before),
                        "revoked": sorted(before - after),
                    },
                )
        db.session.commit()
        flash("Role permissions saved.", "success")
        return redirect(url_for("admin.roles"))
    return render_template("admin/roles.html", form=form, roles=all_roles, permissions=permissions)
