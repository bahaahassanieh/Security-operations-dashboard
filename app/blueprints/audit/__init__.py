"""Audit log viewer and chain verification."""
from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_wtf import FlaskForm

from app.extensions import db
from app.models import ActivityLog, AuditOutcome
from app.services import audit
from app.services.authz import permission_required

audit_bp = Blueprint("audit", __name__, url_prefix="/audit")


class VerifyForm(FlaskForm):
    """Carries the CSRF token for the verify action."""


@audit_bp.route("/")
@permission_required("audit.view")
def index():
    query = db.select(ActivityLog).order_by(ActivityLog.id.desc())
    action = request.args.get("action", "").strip()[:64]
    actor = request.args.get("actor", "").strip()[:64]
    outcome = request.args.get("outcome", "")
    if action:
        escaped = action.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        query = query.where(ActivityLog.action.like(f"{escaped}%", escape="\\"))
    if actor:
        query = query.where(ActivityLog.actor_name == actor)
    if outcome in AuditOutcome.ALL:
        query = query.where(ActivityLog.outcome == outcome)
    page = db.paginate(query, per_page=50, error_out=False)
    return render_template(
        "audit/index.html",
        page=page,
        action=action,
        actor=actor,
        outcome=outcome,
        outcomes=AuditOutcome.ALL,
        verify_form=VerifyForm(),
    )


@audit_bp.route("/verify", methods=["POST"])
@permission_required("audit.view")
def verify():
    form = VerifyForm()
    if form.validate_on_submit():
        status = audit.verify_chain()
        audit.record(
            "audit.verified",
            outcome=AuditOutcome.SUCCESS if status.valid else AuditOutcome.FAILURE,
            details={"entries": status.entries_checked, "first_broken_id": status.first_broken_id},
        )
        db.session.commit()
        flash(
            f"{status.message} {status.entries_checked} entries verified.",
            "success" if status.valid else "danger",
        )
    return redirect(url_for("audit.index"))
