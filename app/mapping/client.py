"""Minimal HTTP client for the crawler.

Safety properties enforced here rather than left to callers:

* Only GET, HEAD and OPTIONS can be sent. The client has no way to submit data.
* Connections go to the IP address validated by the scope gate, so DNS cannot redirect them.
* Redirects are returned to the caller, never followed.
* Response size and total time are bounded, and compressed bodies are never expanded.
"""
from __future__ import annotations

import http.client
import socket
import ssl
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

USER_AGENT = "SentinelPT/0.3 (authorized security assessment)"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
MAX_BODY_BYTES = 2 * 1024 * 1024
CONNECT_TIMEOUT_SECONDS = 10
TOTAL_DEADLINE_SECONDS = 20


class FetchError(Exception):
    """The request could not be completed."""


@dataclass(frozen=True)
class FetchResponse:
    """A bounded HTTP response."""

    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    truncated: bool
    elapsed_ms: int

    def header(self, name: str) -> str:
        name = name.lower()
        return next((value for key, value in self.headers if key.lower() == name), "")

    def header_values(self, name: str) -> list[str]:
        name = name.lower()
        return [value for key, value in self.headers if key.lower() == name]

    @property
    def content_type(self) -> str:
        return self.header("Content-Type").split(";", 1)[0].strip().lower()

    @property
    def text(self) -> str:
        """Decode the body, or return nothing if it is compressed."""
        if self.header("Content-Encoding").lower() not in ("", "identity"):
            return ""
        return self.body.decode("utf-8", errors="replace")


def _tls_context() -> ssl.SSLContext:
    """Assessment targets often use private certificates, and no secrets are sent to them."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # nosec B323  Certificates are reviewed by the TLS module.
    return context


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, pinned_ip: str):
        super().__init__(host, port, timeout=CONNECT_TIMEOUT_SECONDS)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, pinned_ip: str):
        super().__init__(host, port, timeout=CONNECT_TIMEOUT_SECONDS, context=_tls_context())
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        raw = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        hostname = None if self.host == self._pinned_ip else self.host
        self.sock = self._context.wrap_socket(raw, server_hostname=hostname)


def fetch(url: str, pinned_ip: str, method: str = "GET") -> FetchResponse:
    """Send one safe request to ``pinned_ip`` and return a bounded response."""
    if method not in SAFE_METHODS:
        raise ValueError(f"The crawler may not send {method} requests.")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise FetchError("Unsupported URL.")
    secure = parts.scheme == "https"
    port = parts.port or (443 if secure else 80)
    connection_class = _PinnedHTTPSConnection if secure else _PinnedHTTPConnection
    connection = connection_class(parts.hostname, port, pinned_ip)
    target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    started = time.monotonic()
    try:
        connection.request(
            method, target,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"},
        )
        response = connection.getresponse()
        chunks: list[bytes] = []
        size = 0
        truncated = False
        while method != "HEAD":
            if time.monotonic() - started > TOTAL_DEADLINE_SECONDS:
                truncated = True
                break
            chunk = response.read1(64 * 1024)  # Returns as data arrives, so slow senders hit the deadline.
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_BODY_BYTES:
                chunks.append(chunk[: MAX_BODY_BYTES - (size - len(chunk))])
                truncated = True
                break
            chunks.append(chunk)
        return FetchResponse(
            status=response.status,
            headers=tuple(response.getheaders()),
            body=b"".join(chunks),
            truncated=truncated,
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )
    except (OSError, http.client.HTTPException, ValueError) as exc:
        raise FetchError(f"{type(exc).__name__}: {exc}"[:300]) from exc
    finally:
        connection.close()
