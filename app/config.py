"""Application configuration, loaded from the environment.

Secrets are never hardcoded. Production refuses to start without them, see
:meth:`ProductionConfig.validate`.
"""
from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw not in (None, "") else default


def _list(name: str) -> list[str]:
    return [item.strip() for item in os.environ.get(name, "").split(",") if item.strip()]


class BaseConfig:
    """Settings shared by every environment."""

    APP_NAME = "Sentinel PT"
    APP_VERSION = "0.6.0"

    INSTANCE_DIR = Path(os.environ.get("PTP_INSTANCE_DIR", BASE_DIR / "instance"))
    BACKUP_DIR = Path(os.environ.get("PTP_BACKUP_DIR", BASE_DIR / "backups"))
    LOG_DIR = Path(os.environ.get("PTP_LOG_DIR", INSTANCE_DIR / "logs"))
    LOG_LEVEL = os.environ.get("PTP_LOG_LEVEL", "INFO")
    JOB_DIR = Path(os.environ.get("PTP_JOB_DIR", INSTANCE_DIR / "jobs"))
    IMPORT_DIR = Path(os.environ.get("PTP_IMPORT_DIR", INSTANCE_DIR / "imports"))
    IMPORT_MAX_BYTES = _int("PTP_IMPORT_MAX_BYTES", 10 * 1024 * 1024)
    EVIDENCE_DIR = Path(os.environ.get("PTP_EVIDENCE_DIR", INSTANCE_DIR / "evidence"))
    EVIDENCE_MAX_BYTES = _int("PTP_EVIDENCE_MAX_BYTES", 15 * 1024 * 1024)
    REPORT_DIR = Path(os.environ.get("PTP_REPORT_DIR", INSTANCE_DIR / "reports"))
    EVIDENCE_RETENTION_DAYS = _int("PTP_EVIDENCE_RETENTION_DAYS", 365)
    TOOL_DIRS = _list("PTP_TOOL_DIRS") or [
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        str(Path.home() / "go" / "bin"),
    ]
    WORDLIST_PATH = os.environ.get("PTP_WORDLIST", "/usr/share/wordlists/dirb/common.txt")

    SECRET_KEY = os.environ.get("PTP_SECRET_KEY")
    AUDIT_HMAC_KEY = os.environ.get("PTP_AUDIT_KEY")

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "PTP_DATABASE_URI", f"sqlite:///{INSTANCE_DIR / 'platform.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

    # Session cookies
    SESSION_COOKIE_NAME = "ptp_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    SESSION_COOKIE_SECURE = _bool("PTP_COOKIE_SECURE", True)
    SESSION_REFRESH_EACH_REQUEST = True
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=_int("PTP_SESSION_MINUTES", 30))
    REMEMBER_COOKIE_DURATION = timedelta(seconds=0)

    # CSRF
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    WTF_CSRF_SSL_STRICT = _bool("PTP_COOKIE_SECURE", True)

    # Request limits
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024
    MAX_FORM_MEMORY_SIZE = 1024 * 1024
    ALLOWED_HOSTS = _list("PTP_ALLOWED_HOSTS") or ["localhost", "127.0.0.1", "[::1]"]
    PROXY_COUNT = _int("PTP_PROXY_COUNT", 0)

    # Rate limiting
    RATELIMIT_STORAGE_URI = os.environ.get("PTP_RATELIMIT_STORAGE", "memory://")
    RATELIMIT_DEFAULT = os.environ.get("PTP_RATELIMIT_DEFAULT", "300 per minute")
    RATELIMIT_LOGIN = os.environ.get("PTP_RATELIMIT_LOGIN", "10 per minute")
    RATELIMIT_HEADERS_ENABLED = True
    RATELIMIT_ENABLED = True

    # Password policy
    PASSWORD_MIN_LENGTH = 12

    @classmethod
    def validate(cls) -> None:
        """Hook for environment-specific start-up checks."""


class DevelopmentConfig(BaseConfig):
    """Local development only. Keys are ephemeral unless provided."""

    DEBUG = False  # The Werkzeug debugger is remote code execution; never enable it.
    SESSION_COOKIE_SECURE = False
    WTF_CSRF_SSL_STRICT = False


class TestingConfig(BaseConfig):
    """Pytest configuration."""

    TESTING = True
    SECRET_KEY = "test-secret-key-not-used-outside-pytest-000000"  # nosec B105
    AUDIT_HMAC_KEY = "test-audit-key-not-used-outside-pytest-0000000"  # nosec B105
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SESSION_COOKIE_SECURE = False
    WTF_CSRF_ENABLED = False
    WTF_CSRF_SSL_STRICT = False
    RATELIMIT_ENABLED = False
    ALLOWED_HOSTS = None


class ProductionConfig(BaseConfig):
    """Served by Gunicorn. Refuses to start with missing or weak secrets."""

    @classmethod
    def validate(cls) -> None:
        for name, value in (
            ("PTP_SECRET_KEY", cls.SECRET_KEY),
            ("PTP_AUDIT_KEY", cls.AUDIT_HMAC_KEY),
        ):
            if not value or len(value) < 32:
                raise RuntimeError(
                    f"{name} must be set to at least 32 characters. "
                    "Run scripts/setup.sh to generate a configuration."
                )


CONFIGS = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}
