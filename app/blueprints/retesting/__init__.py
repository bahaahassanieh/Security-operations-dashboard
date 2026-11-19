"""Remediation tracking and retesting."""
from __future__ import annotations

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user
from flask_wtf import FlaskForm

from app.extensions import db
from app.findings.service import FindingError
from app.models import Engagement, RemediationStatus, Vulnerability
from app.reporting import remediation as remediation_service
from app.services import engagements as engagement_service
from app.services.authz import permission_required

retesting_bp = Blueprint("retesting", __name__, url_prefix="/retesting")


class ActionForm(FlaskForm):
    """Carries the CSRF token for remediation and retest actions."""


def _engagements():
    return db.session.scalars(
        engagement_service.visible_engagements_query(current_user).order_by(Engagement.created_at.desc())
    ).all()


def _finding_or_404(finding_id: int) -> Vulnerability:
    row = db.session.get(Vulnerability, finding_id)
    if row is None or engagement_service.get_visible_engagement(current_user, row.engagement_id) is None:
        abort(404)
    return row


@retesting_bp.route("/")
@permission_required("findings.view")
def index():
    engagements = _engagements()
    selected_id = request.args.get("engagement", type=int)
    if selected_id is None and engagements:
        selected_id = engagements[0].id
    selected = next((item for item in engagements if item.id == selected_id), None)
    if selected_id is not None and selected is None:
        abort(404)
    queue = remediation_service.retest_queue(selected.id) if selected else []
    return render_template(
        "retesting/index.html", engagements=engagements, selected=selected, queue=queue,
        results=remediation_service.RETEST_RESULTS, statuses=RemediationStatus.ALL, form=ActionForm(),
    )


@retesting_bp.route("/findings/<int:finding_id>/remediation", methods=["POST"])
@permission_required("findings.manage")
def remediation(finding_id: int):
    finding = _finding_or_404(finding_id)
    if ActionForm().validate_on_submit():
        try:
            remediation_service.update_remediation(
                finding, current_user, request.form.get("status", ""), request.form.get("owner", ""),
                request.form.get("due", ""), request.form.get("notes", ""),
            )
        except FindingError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            db.session.commit()
            flash("Remediation updated.", "success")
    return redirect(request.form.get("next") or url_for("retesting.index", engagement=finding.engagement_id))


@retesting_bp.route("/findings/<int:finding_id>/retest", methods=["POST"])
@permission_required("findings.validate")
def retest(finding_id: int):
    finding = _finding_or_404(finding_id)
    if ActionForm().validate_on_submit():
        try:
            remediation_service.record_retest(
                finding, current_user, request.form.get("result", ""), request.form.get("notes", ""),
                request.form.get("evidence_id", type=int),
            )
        except FindingError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            db.session.commit()
            flash("Retest recorded.", "success")
    return redirect(request.form.get("next") or url_for("retesting.index", engagement=finding.engagement_id))
