"""Application factory."""
from __future__ import annotations

import logging
import os
import sqlite3
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask
from sqlalchemy import event
from sqlalchemy.engine import Engine
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

# Imported after load_dotenv because configuration classes read the environment.
from app.config import BASE_DIR, CONFIGS  # noqa: E402
from app.extensions import csrf, db, limiter, login_manager, migrate  # noqa: E402
from app.logging_config import configure_logging  # noqa: E402
from app.web import TrustedHostMiddleware, register_web_layer  # noqa: E402


@event.listens_for(Engine, "connect")
def _configure_sqlite(connection, _record) -> None:
    """Enable WAL, foreign keys and lock waiting on every SQLite connection."""
    if isinstance(connection, sqlite3.Connection):
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()


def create_app(config_name: str | None = None, overrides: dict | None = None) -> Flask:
    """Build and configure a Flask application."""
    name = config_name or os.environ.get("PTP_ENV", "production")
    config = CONFIGS[name]
    config.validate()

    app = Flask(__name__, instance_path=str(config.INSTANCE_DIR), instance_relative_config=False)
    app.config.from_object(config)
    app.config.update(overrides or {})

    if name != "testing":
        os.umask(0o077)
        config.INSTANCE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    if name == "development":
        app.config["SECRET_KEY"] = app.config["SECRET_KEY"] or os.urandom(32).hex()
        app.config["AUDIT_HMAC_KEY"] = app.config["AUDIT_HMAC_KEY"] or "development-only-audit-key"

    configure_logging(app)

    if app.config["ALLOWED_HOSTS"]:
        app.wsgi_app = TrustedHostMiddleware(app.wsgi_app, app.config["ALLOWED_HOSTS"])
    if app.config["PROXY_COUNT"]:
        count = app.config["PROXY_COUNT"]
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=count, x_proto=count, x_host=count)

    db.init_app(app)
    migrate.init_app(app, db, directory=str(BASE_DIR / "migrations"))
    csrf.init_app(app)
    limiter.init_app(app)
    login_manager.init_app(app)

    register_web_layer(app)

    from app.cli import ptp_cli

    app.cli.add_command(ptp_cli)
    logging.getLogger("ptp").info("application_started", extra={"event": "startup", "env": name})
    return app
