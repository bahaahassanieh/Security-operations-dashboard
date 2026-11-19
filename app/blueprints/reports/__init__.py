"""Report generation, download and the CVSS calculator."""
from __future__ import annotations

from flask import Blueprint, abort, flash, jsonify, redirect, render_template, request, send_file, url_for
from flask_login import current_user
from flask_wtf import FlaskForm

from app.extensions import db
from app.findings.service import FindingError
from app.models import Engagement, Report
from app.reporting import cvss
from app.reporting import service as reports
from app.reporting.render import REPORT_TITLES
from app.services import engagements as engagement_service
from app.services.authz import permission_required

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


class ActionForm(FlaskForm):
    """Carries the CSRF token for report actions."""


def _engagements():
    return db.session.scalars(
        engagement_service.visible_engagements_query(current_user).order_by(Engagement.created_at.desc())
    ).all()


def _report_or_404(report_id: int) -> Report:
    report = db.session.get(Report, report_id)
    if report is None or engagement_service.get_visible_engagement(current_user, report.engagement_id) is None:
        abort(404)
    return report


@reports_bp.route("/")
@permission_required("reports.view")
def index():
    engagements = _engagements()
    selected_id = request.args.get("engagement", type=int)
    if selected_id is None and engagements:
        selected_id = engagements[0].id
    selected = next((item for item in engagements if item.id == selected_id), None)
    if selected_id is not None and selected is None:
        abort(404)
    history = []
    if selected is not None:
        history = db.session.scalars(
            db.select(Report).filter_by(engagement_id=selected.id).order_by(Report.id.desc()).limit(50)
        ).all()
    return render_template(
        "reports/index.html", engagements=engagements, selected=selected, history=history,
        report_titles=REPORT_TITLES, form=ActionForm(),
    )


@reports_bp.route("/generate", methods=["POST"])
@permission_required("reports.generate")
def generate():
    engagement = engagement_service.get_visible_engagement(current_user, request.form.get("engagement", type=int) or 0)
    if engagement is None:
        abort(404)
    if ActionForm().validate_on_submit():
        options = {"include_unverified": request.form.get("include_unverified") == "y",
                   "include_evidence": request.form.get("include_evidence") == "y"}
        try:
            report = reports.generate(engagement, current_user, request.form.get("report_type", ""), request.form.get("format", ""), options)
        except FindingError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            db.session.commit()
            flash("Report generated.", "success")
            return redirect(url_for("reports.download", report_id=report.id))
    return redirect(url_for("reports.index", engagement=engagement.id))


@reports_bp.route("/<int:report_id>/download")
@permission_required("reports.view")
def download(report_id: int):
    report = _report_or_404(report_id)
    try:
        path = reports.report_file_path(report)
    except FindingError:
        abort(404)
    mimetype = "application/pdf" if report.output_format == "pdf" else "text/html"
    suffix = "pdf" if report.output_format == "pdf" else "html"
    safe_client = "".join(c for c in report.engagement.name if c.isalnum() or c in " -_")[:40].strip() or "engagement"
    name = f"{report.report_type}-{safe_client}.{suffix}".replace(" ", "_")
    return send_file(path, mimetype=mimetype, as_attachment=True, download_name=name)


@reports_bp.route("/<int:report_id>/delete", methods=["POST"])
@permission_required("reports.generate")
def delete(report_id: int):
    report = _report_or_404(report_id)
    engagement_id = report.engagement_id
    if ActionForm().validate_on_submit():
        try:
            reports.delete_report(report, current_user)
        except FindingError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            db.session.commit()
            flash("Report deleted.", "success")
    return redirect(url_for("reports.index", engagement=engagement_id))


@reports_bp.route("/cvss")
@permission_required("findings.view")
def cvss_calculator():
    return render_template("reports/cvss.html", metrics=cvss.METRICS)


@reports_bp.route("/cvss/score", methods=["POST"])
@permission_required("findings.view")
def cvss_score():
    payload = request.get_json(silent=True) or {}
    try:
        result = cvss.compute({code: payload.get(code, "") for code, _, _ in cvss.METRICS})
    except cvss.CvssError as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(result.as_dict())
