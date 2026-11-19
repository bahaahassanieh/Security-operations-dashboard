"""Application map: endpoint relationships, parameters, forms and cookies."""
from __future__ import annotations

from sqlalchemy import UniqueConstraint

from app.extensions import db
from app.models.base import TimestampMixin, enum_check

LINK_TYPES = ("link", "form", "script", "frame", "redirect", "javascript", "sitemap", "api_spec")
PARAMETER_LOCATIONS = ("query", "form", "path", "header", "cookie", "json")
CRAWL_STATES = (
    "fetched",
    "not_requested",
    "skipped_unsafe",
    "skipped_robots",
    "skipped_static",
    "out_of_scope",
    "error",
)


class EndpointLink(TimestampMixin, db.Model):
    """A directed relationship between two endpoints."""

    __tablename__ = "endpoint_links"
    __table_args__ = (
        UniqueConstraint("source_id", "target_id", "link_type", name="uq_endpoint_link"),
        enum_check("link_type", LINK_TYPES, "link_type_valid"),
    )

    id = db.Column(db.Integer, primary_key=True)
    engagement_id = db.Column(
        db.Integer, db.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_id = db.Column(
        db.Integer, db.ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_id = db.Column(
        db.Integer, db.ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    link_type = db.Column(db.String(16), nullable=False, default="link")

    source = db.relationship("Endpoint", foreign_keys=[source_id])
    target = db.relationship("Endpoint", foreign_keys=[target_id])


class EndpointParameter(TimestampMixin, db.Model):
    """A request parameter. Observed values are deliberately never stored."""

    __tablename__ = "endpoint_parameters"
    __table_args__ = (
        UniqueConstraint("endpoint_id", "name", "location", name="uq_endpoint_parameter"),
        enum_check("location", PARAMETER_LOCATIONS, "location_valid"),
    )

    id = db.Column(db.Integer, primary_key=True)
    engagement_id = db.Column(
        db.Integer, db.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    endpoint_id = db.Column(
        db.Integer, db.ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name = db.Column(db.String(128), nullable=False, index=True)
    location = db.Column(db.String(16), nullable=False)
    data_type = db.Column(db.String(32))
    required = db.Column(db.Boolean, nullable=False, default=False)
    source = db.Column(db.String(32), nullable=False, default="crawler")

    endpoint = db.relationship("Endpoint")


class WebForm(TimestampMixin, db.Model):
    """An HTML form found on a page. The crawler never submits forms."""

    __tablename__ = "web_forms"
    __table_args__ = (
        UniqueConstraint("page_id", "action_id", "fields_fingerprint", name="uq_web_form"),
    )

    id = db.Column(db.Integer, primary_key=True)
    engagement_id = db.Column(
        db.Integer, db.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    page_id = db.Column(
        db.Integer, db.ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action_id = db.Column(
        db.Integer, db.ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    method = db.Column(db.String(10), nullable=False, default="GET")
    enctype = db.Column(db.String(64))
    purpose = db.Column(db.String(24), nullable=False, default="generic", index=True)
    fields = db.Column(db.JSON, nullable=False, default=list)
    fields_fingerprint = db.Column(db.String(64), nullable=False)
    has_password = db.Column(db.Boolean, nullable=False, default=False)
    has_file_upload = db.Column(db.Boolean, nullable=False, default=False)
    has_csrf_token = db.Column(db.Boolean, nullable=False, default=False)

    page = db.relationship("Endpoint", foreign_keys=[page_id])
    action = db.relationship("Endpoint", foreign_keys=[action_id])


class WebCookie(TimestampMixin, db.Model):
    """A cookie's name and attributes. Cookie values are deliberately never stored."""

    __tablename__ = "web_cookies"
    __table_args__ = (
        UniqueConstraint("engagement_id", "host", "name", "path", name="uq_web_cookie"),
    )

    id = db.Column(db.Integer, primary_key=True)
    engagement_id = db.Column(
        db.Integer, db.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    endpoint_id = db.Column(db.Integer, db.ForeignKey("endpoints.id", ondelete="SET NULL"), index=True)
    host = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(128), nullable=False, index=True)
    path = db.Column(db.String(255), nullable=False, default="/")
    domain = db.Column(db.String(255))
    secure = db.Column(db.Boolean, nullable=False, default=False)
    http_only = db.Column(db.Boolean, nullable=False, default=False)
    same_site = db.Column(db.String(16))
    persistent = db.Column(db.Boolean, nullable=False, default=False)

    endpoint = db.relationship("Endpoint")
