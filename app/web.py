"""Blueprint registration, request hooks, security headers and error handling."""
from __future__ import annotations

import logging
import uuid

from flask import Flask, g, jsonify, redirect, render_template, request, session, url_for
from flask_login import current_user
from flask_wtf.csrf import CSRFError, generate_csrf
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.exceptions import HTTPException

from app.extensions import db, limiter, login_manager
from app.models import User
from app.navigation import build_navigation

logger = logging.getLogger("ptp.web")

CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "form-action 'self'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
    )
)
_PASSWORD_CHANGE_EXEMPT = {"auth.change_password", "auth.logout", "static"}


class TrustedHostMiddleware:
    """Reject unknown Host headers before routing, so no URL is ever built from one."""

    def __init__(self, wsgi_app, allowed_hosts: list[str]):
        self.wsgi_app = wsgi_app
        self.allowed_hosts = {self._hostname(host) for host in allowed_hosts}

    @staticmethod
    def _hostname(value: str) -> str:
        """Drop any port, keeping bracketed IPv6 literals intact."""
        value = value.strip().lower()
        if value.startswith("["):
            return value.partition("]")[0] + "]"
        return value.partition(":")[0]

    def __call__(self, environ, start_response):
        host = environ.get("HTTP_HOST") or environ.get("SERVER_NAME", "")
        if self._hostname(host) in self.allowed_hosts:
            return self.wsgi_app(environ, start_response)
        body = b"Bad Request: untrusted host\n"
        start_response(
            "400 Bad Request",
            [("Content-Type", "text/plain"), ("Content-Length", str(len(body)))],
        )
        return [body]


@login_manager.user_loader
def load_user(session_id: str) -> User | None:
    """Load a user only while the session's token still matches the account."""
    user_id, _, token = session_id.partition(":")
    if not user_id.isdigit() or not token:
        return None
    user = db.session.get(User, int(user_id))
    if user is None or not user.is_enabled or user.session_token != token:
        return None
    return user


@login_manager.unauthorized_handler
def handle_unauthorized():
    if request.path.startswith("/api/"):
        return jsonify(error="authentication_required"), 401
    return redirect(url_for("auth.login", next=request.full_path.rstrip("?")))


def _wants_json() -> bool:
    return request.path.startswith("/api/")


def register_web_layer(app: Flask) -> None:
    """Attach blueprints, hooks, headers and error handlers."""
    from app.blueprints.admin import admin_bp
    from app.blueprints.api import api_bp
    from app.blueprints.apitest import apitest_bp
    from app.blueprints.assets import assets_bp
    from app.blueprints.audit import audit_bp
    from app.blueprints.auth import auth_bp
    from app.blueprints.evidence import evidence_bp
    from app.blueprints.dashboard import dashboard_bp
    from app.blueprints.engagements import engagements_bp
    from app.blueprints.findings import findings_bp
    from app.blueprints.health import health_bp
    from app.blueprints.manual import manual_bp
    from app.blueprints.mapping import mapping_bp
    from app.blueprints.methodology import methodology_bp
    from app.blueprints.reports import reports_bp
    from app.blueprints.retesting import retesting_bp
    from app.blueprints.recon import recon_bp
    from app.blueprints.tools import tools_bp

    for blueprint in (
        auth_bp, dashboard_bp, engagements_bp, admin_bp, audit_bp, api_bp, health_bp,
        tools_bp, recon_bp, assets_bp, mapping_bp, findings_bp, methodology_bp,
        manual_bp, apitest_bp, evidence_bp, reports_bp, retesting_bp,
    ):
        app.register_blueprint(blueprint)
    limiter.exempt(health_bp)

    login_manager.session_protection = "strong"
    login_manager.login_view = "auth.login"

    @app.before_request
    def prepare_request():
        g.request_id = str(uuid.uuid4())
        session.permanent = True

    @app.before_request
    def enforce_password_change():
        """Keep users with a temporary password away from everything else."""
        if (
            current_user.is_authenticated
            and current_user.must_change_password
            and request.endpoint not in _PASSWORD_CHANGE_EXEMPT
            and not (request.endpoint or "").startswith("health.")
        ):
            if _wants_json():
                return jsonify(error="password_change_required"), 403
            return redirect(url_for("auth.change_password"))
        return None

    @app.after_request
    def apply_security_headers(response):
        response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["X-Request-ID"] = g.get("request_id", "")
        if app.config["SESSION_COOKIE_SECURE"]:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.context_processor
    def inject_template_globals():
        from flask import has_request_context
        if not has_request_context():
            return {"app_name": app.config["APP_NAME"], "app_version": app.config["APP_VERSION"]}
        return {
            "app_name": app.config["APP_NAME"],
            "app_version": app.config["APP_VERSION"],
            "navigation": build_navigation(current_user, request.endpoint),
            "csrf_token": generate_csrf,
        }

    @app.template_filter("datetime_utc")
    def format_datetime(value):
        return value.strftime("%Y-%m-%d %H:%M UTC") if value else "—"

    @app.errorhandler(CSRFError)
    def handle_csrf(error):
        logger.warning("csrf_rejected", extra={"event": "csrf", "path": request.path})
        if _wants_json():
            return jsonify(error="csrf_failed"), 400
        return render_template("errors/error.html", code=400, message=error.description), 400

    @app.errorhandler(HTTPException)
    def handle_http_error(error):
        if _wants_json():
            return jsonify(error=error.name.lower().replace(" ", "_")), error.code
        return render_template("errors/error.html", code=error.code, message=error.description), error.code

    @app.errorhandler(SQLAlchemyError)
    def handle_database_error(error):
        db.session.rollback()
        logger.exception("database_error", exc_info=error)
        if _wants_json():
            return jsonify(error="internal_error"), 500
        return render_template("errors/error.html", code=500, message="A database error occurred."), 500

    @app.errorhandler(Exception)
    def handle_unexpected(error):
        db.session.rollback()
        logger.exception("unhandled_exception", exc_info=error)
        if _wants_json():
            return jsonify(error="internal_error"), 500
        return render_template("errors/error.html", code=500, message="An unexpected error occurred."), 500
