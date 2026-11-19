"""Authentication routes: login, logout and password change."""
from __future__ import annotations

from urllib.parse import urlsplit

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length

from app.extensions import db, limiter
from app.services import accounts, audit

auth_bp = Blueprint("auth", __name__)


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=64)])
    password = PasswordField("Password", validators=[DataRequired(), Length(max=256)])
    submit = SubmitField("Sign in")


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current password", validators=[DataRequired(), Length(max=256)])
    new_password = PasswordField("New password", validators=[DataRequired(), Length(max=256)])
    confirm_password = PasswordField(
        "Confirm new password",
        validators=[DataRequired(), EqualTo("new_password", "Passwords do not match.")],
    )
    submit = SubmitField("Change password")


def safe_next_url(target: str | None) -> str:
    """Allow only same-site relative redirects, which blocks open redirects."""
    default = url_for("dashboard.index")
    if not target or not target.startswith("/") or target.startswith(("//", "/\\")):
        return default
    if any(ord(char) < 0x20 for char in target) or "\\" in target:
        return default
    parts = urlsplit(target)
    return target if not parts.scheme and not parts.netloc else default


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config["RATELIMIT_LOGIN"], methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    form = LoginForm()
    if form.validate_on_submit():
        user = accounts.authenticate(form.username.data, form.password.data)
        if user is not None:
            session.clear()  # Prevents session fixation.
            login_user(user)
            return redirect(safe_next_url(request.args.get("next")))
        flash("Invalid username or password, or the account is unavailable.", "danger")
    return render_template("auth/login.html", form=form)


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    user = current_user._get_current_object()
    user.rotate_session_token()  # A copied session cookie stops working immediately.
    audit.record("auth.logout", actor=user, object_type="user", object_id=user.id)
    db.session.commit()
    logout_user()
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/account/password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        user = current_user._get_current_object()
        try:
            accounts.change_password(user, form.current_password.data, form.new_password.data)
        except accounts.AccountError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            db.session.commit()
            session.clear()
            login_user(user)  # Keep this session; every other session is now revoked.
            flash("Password changed. Other sessions have been signed out.", "success")
            return redirect(url_for("dashboard.index"))
    return render_template("auth/change_password.html", form=form)
