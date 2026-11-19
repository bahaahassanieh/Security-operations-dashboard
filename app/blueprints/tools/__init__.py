"""Tool management. Paths are detected, never configurable, so no page can launch a program."""
from __future__ import annotations

from flask import Blueprint, abort, flash, redirect, render_template, url_for
from flask_wtf import FlaskForm

from app.extensions import db
from app.models import ToolRegistry
from app.services import audit
from app.services.authz import permission_required
from app.tools import registry

tools_bp = Blueprint("tools", __name__, url_prefix="/tools")


class ActionForm(FlaskForm):
    """Carries the CSRF token for button-only actions."""


@tools_bp.route("/")
@permission_required("engagement.view")
def index():
    rows = db.session.scalars(
        db.select(ToolRegistry).order_by(ToolRegistry.category, ToolRegistry.display_name)
    ).all()
    if not rows:
        rows = registry.sync_registry()
    summary = {
        "total": len(rows),
        "healthy": sum(row.health_status == "healthy" for row in rows),
        "degraded": sum(row.health_status == "degraded" for row in rows),
        "missing": sum(row.health_status == "missing" for row in rows),
    }
    return render_template(
        "tools/index.html", rows=rows, summary=summary, form=ActionForm(), definitions=registry.TOOLS
    )


@tools_bp.route("/refresh", methods=["POST"])
@permission_required("tools.manage")
def refresh():
    if ActionForm().validate_on_submit():
        rows = registry.sync_registry()
        audit.record("tools.refreshed", details={"tools": len(rows)})
        db.session.commit()
        flash("Tool detection finished.", "success")
    return redirect(url_for("tools.index"))


@tools_bp.route("/<int:tool_id>/toggle", methods=["POST"])
@permission_required("tools.manage")
def toggle(tool_id: int):
    row = db.session.get(ToolRegistry, tool_id)
    if row is None:
        abort(404)
    if ActionForm().validate_on_submit():
        row.is_enabled = not row.is_enabled
        audit.record(
            "tools.toggled", object_type="tool", object_id=row.name,
            details={"enabled": row.is_enabled},
        )
        db.session.commit()
        flash(f"{row.display_name} {'enabled' if row.is_enabled else 'disabled'}.", "success")
    return redirect(url_for("tools.index"))
