"""Liveness and readiness probes. They reveal no configuration or version details."""
from __future__ import annotations

import logging

from flask import Blueprint, jsonify
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.extensions import db

health_bp = Blueprint("health", __name__)
logger = logging.getLogger("ptp.health")


@health_bp.route("/healthz")
def liveness():
    return jsonify(status="ok")


@health_bp.route("/readyz")
def readiness():
    try:
        db.session.execute(text("SELECT 1 FROM alembic_version"))
    except SQLAlchemyError:
        db.session.rollback()
        logger.exception("readiness_check_failed")
        return jsonify(status="unavailable"), 503
    return jsonify(status="ready")
