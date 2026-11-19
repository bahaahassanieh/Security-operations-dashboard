"""Structured JSON logging."""
from __future__ import annotations

import json
import logging
import logging.handlers
from datetime import datetime, timezone

from flask import Flask, g, has_request_context

_STANDARD_ATTRS = set(logging.makeLogRecord({}).__dict__) | {"message", "asctime", "taskName"}


class JsonFormatter(logging.Formatter):
    """Render each log record as one JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if has_request_context() and g.get("request_id"):
            payload["request_id"] = g.request_id
        payload.update(
            {key: value for key, value in record.__dict__.items() if key not in _STANDARD_ATTRS}
        )
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(app: Flask) -> None:
    """Send structured logs to stderr and, outside tests, a rotating file."""
    formatter = JsonFormatter()
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if not app.testing:
        log_dir = app.config["LOG_DIR"]
        log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        handlers.append(
            logging.handlers.RotatingFileHandler(
                log_dir / "platform.log", maxBytes=10 * 1024 * 1024, backupCount=5
            )
        )
    logger = logging.getLogger("ptp")
    logger.handlers.clear()
    logger.setLevel(app.config["LOG_LEVEL"])
    logger.propagate = False
    for handler in handlers:
        handler.setFormatter(formatter)
        logger.addHandler(handler)
