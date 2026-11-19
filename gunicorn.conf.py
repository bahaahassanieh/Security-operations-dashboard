"""Production server settings. Refuses to expose plaintext session cookies on the network."""
import ipaddress
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

_host = os.environ.get("PTP_BIND_HOST", "127.0.0.1")
_port = int(os.environ.get("PTP_BIND_PORT", "8088"))
_cookie_secure = os.environ.get("PTP_COOKIE_SECURE", "true").strip().lower() in {"1", "true", "yes", "on"}


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


if not _is_loopback(_host) and not _cookie_secure:
    raise SystemExit(
        "Refusing to bind to a network address with PTP_COOKIE_SECURE=false. "
        "Put the platform behind TLS and set PTP_COOKIE_SECURE=true (see docs/DEPLOYMENT.md)."
    )

bind = f"{_host}:{_port}"
workers = int(os.environ.get("PTP_WORKERS", "2"))
threads = int(os.environ.get("PTP_THREADS", "4"))
worker_class = "gthread"
timeout = 60
graceful_timeout = 30
keepalive = 5
max_requests = 2000
max_requests_jitter = 200
limit_request_line = 8190
limit_request_fields = 100
umask = 0o077
accesslog = "-"
errorlog = "-"
loglevel = "info"
# Query strings are omitted because they can contain search terms and targets.
access_log_format = '%(h)s "%(m)s %(U)s" %(s)s %(b)s %(M)sms'
