"""Discovered attack surface: assets, subdomains, endpoints and technologies."""
from __future__ import annotations

from sqlalchemy import CheckConstraint, UniqueConstraint

from app.extensions import db
from app.models.base import TimestampMixin, enum_check, utcnow

ASSET_TYPES = ("domain", "host", "ip", "web_service", "network_service", "certificate")


class Asset(TimestampMixin, db.Model):
    """A discovered host, service or certificate."""

    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("engagement_id", "asset_type", "value", "port", name="uq_asset_identity"),
        enum_check("asset_type", ASSET_TYPES, "asset_type_valid"),
        CheckConstraint("port IS NULL OR (port BETWEEN 1 AND 65535)", name="port_range"),
    )

    id = db.Column(db.Integer, primary_key=True)
    engagement_id = db.Column(
        db.Integer, db.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_id = db.Column(db.Integer, db.ForeignKey("targets.id", ondelete="SET NULL"), index=True)
    asset_type = db.Column(db.String(24), nullable=False)
    value = db.Column(db.String(2048), nullable=False)
    ip_address = db.Column(db.String(45), index=True)
    port = db.Column(db.Integer)
    protocol = db.Column(db.String(16))
    service = db.Column(db.String(64))
    source = db.Column(db.String(64), nullable=False, default="manual")
    in_scope = db.Column(db.Boolean, nullable=False, default=False, index=True)
    attributes = db.Column(db.JSON, nullable=False, default=dict)
    first_seen = db.Column(db.DateTime, nullable=False, default=utcnow)
    last_seen = db.Column(db.DateTime, nullable=False, default=utcnow)


class Subdomain(TimestampMixin, db.Model):
    """A discovered hostname and its DNS data."""

    __tablename__ = "subdomains"
    __table_args__ = (UniqueConstraint("engagement_id", "hostname", name="uq_subdomain_host"),)

    id = db.Column(db.Integer, primary_key=True)
    engagement_id = db.Column(
        db.Integer, db.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id", ondelete="SET NULL"), index=True)
    hostname = db.Column(db.String(255), nullable=False, index=True)
    dns_records = db.Column(db.JSON, nullable=False, default=dict)
    resolved_ips = db.Column(db.JSON, nullable=False, default=list)
    source = db.Column(db.String(64), nullable=False, default="manual")
    is_alive = db.Column(db.Boolean, nullable=False, default=False)
    in_scope = db.Column(db.Boolean, nullable=False, default=False, index=True)


class Endpoint(TimestampMixin, db.Model):
    """An entry in the application's endpoint inventory."""

    __tablename__ = "endpoints"
    __table_args__ = (
        UniqueConstraint("engagement_id", "method", "url", name="uq_endpoint_identity"),
    )

    id = db.Column(db.Integer, primary_key=True)
    engagement_id = db.Column(
        db.Integer, db.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id", ondelete="SET NULL"), index=True)
    parent_id = db.Column(db.Integer, db.ForeignKey("endpoints.id", ondelete="SET NULL"), index=True)
    url = db.Column(db.String(2048), nullable=False)
    path = db.Column(db.String(2048), nullable=False, default="/")
    method = db.Column(db.String(10), nullable=False, default="GET")
    parameters = db.Column(db.JSON, nullable=False, default=list)
    category = db.Column(db.String(48), index=True)
    status_code = db.Column(db.Integer)
    content_type = db.Column(db.String(128))
    requires_auth = db.Column(db.Boolean)
    redirect_location = db.Column(db.String(2048))
    source = db.Column(db.String(64), nullable=False, default="manual")
    in_scope = db.Column(db.Boolean, nullable=False, default=False, index=True)
    title = db.Column(db.String(255))
    crawl_state = db.Column(db.String(24), index=True)
    depth = db.Column(db.Integer)
    allowed_methods = db.Column(db.String(128))

    parent = db.relationship("Endpoint", remote_side=[id])


class Technology(TimestampMixin, db.Model):
    """A fingerprinted technology on an asset."""

    __tablename__ = "technologies"
    __table_args__ = (
        UniqueConstraint("engagement_id", "asset_id", "name", "version", name="uq_technology"),
        CheckConstraint("confidence BETWEEN 0 AND 100", name="confidence_range"),
    )

    id = db.Column(db.Integer, primary_key=True)
    engagement_id = db.Column(
        db.Integer, db.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    name = db.Column(db.String(128), nullable=False, index=True)
    version = db.Column(db.String(64), nullable=False, default="")
    category = db.Column(db.String(64))
    confidence = db.Column(db.Integer, nullable=False, default=50)
    source = db.Column(db.String(64), nullable=False, default="manual")
