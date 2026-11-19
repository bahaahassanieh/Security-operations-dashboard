"""Findings, validation workflow and the scanner results upload panel."""
from __future__ import annotations

import json

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user
from flask_wtf import FlaskForm
from sqlalchemy import case, func, or_
from werkzeug.exceptions import RequestEntityTooLarge

from app.extensions import db
from app.findings import parsers, service, taxonomy
from app.models import (
    Engagement,
    FindingImport,
    FindingSource,
    Severity,
    ValidationStatus,
    Vulnerability,
)
from app.services import engagements as engagement_service
from app.services.authz import permission_required

findings_bp = Blueprint("findings", __name__, url_prefix="/findings")

GENERIC_TEMPLATE = {
    "source": "my_engine",
    "findings": [
        {
            "name": "Reflected cross-site scripting",
            "severity": "high",
            "url": "https://app.example.com/search",
            "method": "GET",
            "parameter": "q",
            "description": "What the engine detected.",
            "remediation": "How to fix it.",
            "cwe": "CWE-79",
            "cvss_score": 6.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "references": ["https://owasp.org/www-community/attacks/xss/"],
            "evidence": "Request and response excerpt.",
            "confidence": "firm",
        }
    ],
}
UPLOAD_CONFIRMATION = (
    "I confirm these results came from testing covered by this engagement's recorded client authorization."
)


class ActionForm(FlaskForm):
    """Carries the CSRF token for forms whose fields are read directly."""


@findings_bp.url_value_preprocessor
def allow_report_uploads(endpoint, _values) -> None:
    """Raise the request size limit for the upload route only, before the body is read."""
    if endpoint == "findings.imports" and request.method == "POST":
        request.max_content_length = current_app.config["IMPORT_MAX_BYTES"] + 64 * 1024


def _visible_engagements() -> list[Engagement]:
    query = engagement_service.visible_engagements_query(current_user)
    return db.session.scalars(query.order_by(Engagement.created_at.desc())).all()


def _finding_or_404(finding_id: int) -> Vulnerability:
    row = db.session.get(Vulnerability, finding_id)
    if row is None or engagement_service.get_visible_engagement(current_user, row.engagement_id) is None:
        abort(404)
    return row


def _selected(engagements: list[Engagement]) -> Engagement | None:
    selected_id = request.values.get("engagement", type=int)
    if selected_id is None:
        return engagements[0] if engagements else None
    selected = next((item for item in engagements if item.id == selected_id), None)
    if selected is None:
        abort(404)
    return selected


@findings_bp.route("/")
@permission_required("findings.view")
def finding_list():
    engagements = _visible_engagements()
    selected = _selected(engagements)
    filters = {
        "severity": request.args.get("severity", ""),
        "status": request.args.get("status", ""),
        "source": request.args.get("source", "")[:64],
        "q": request.args.get("q", "").strip()[:100],
    }
    page, sources, summary = None, [], {}
    if selected is not None:
        base = db.select(Vulnerability).filter_by(engagement_id=selected.id)
        counts = dict(
            db.session.execute(
                db.select(Vulnerability.validation_status, func.count())
                .filter_by(engagement_id=selected.id).group_by(Vulnerability.validation_status)
            ).all()
        )
        summary = {
            "total": sum(counts.values()),
            "awaiting": sum(counts.get(item, 0) for item in ValidationStatus.UNCONFIRMED),
            "confirmed": counts.get(ValidationStatus.CONFIRMED, 0),
            "false_positive": counts.get(ValidationStatus.FALSE_POSITIVE, 0),
        }
        sources = db.session.scalars(
            db.select(FindingSource.source).join(Vulnerability)
            .where(Vulnerability.engagement_id == selected.id).distinct().order_by(FindingSource.source)
        ).all()
        rows = base
        if filters["severity"] in Severity.ALL:
            rows = rows.where(Vulnerability.severity == filters["severity"])
        if filters["status"] == "awaiting":
            rows = rows.where(Vulnerability.validation_status.in_(ValidationStatus.UNCONFIRMED))
        elif filters["status"] in ValidationStatus.ALL:
            rows = rows.where(Vulnerability.validation_status == filters["status"])
        if filters["source"]:
            rows = rows.where(Vulnerability.sources.any(FindingSource.source == filters["source"]))
        if filters["q"]:
            pattern = "%" + filters["q"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            rows = rows.where(
                or_(Vulnerability.name.ilike(pattern, escape="\\"), Vulnerability.endpoint_url.ilike(pattern, escape="\\"))
            )
        rank = case({level: index for index, level in enumerate(Severity.ALL)}, value=Vulnerability.severity)
        page = db.paginate(rows.order_by(rank, Vulnerability.id.desc()), per_page=50, error_out=False)
    return render_template(
        "findings/index.html", engagements=engagements, selected=selected, page=page, filters=filters,
        sources=sources, summary=summary, severities=Severity.ALL, statuses=ValidationStatus.ALL,
    )


@findings_bp.route("/imports", methods=["GET", "POST"])
@permission_required("findings.view")
def imports():
    engagements = _visible_engagements()
    selected = _selected(engagements)
    form = ActionForm()
    if request.method == "POST":
        if not current_user.has_permission("findings.manage"):
            abort(403)
        if form.validate_on_submit():
            result = _handle_upload(selected)
            if result is not None:
                return result
    history = []
    if selected is not None:
        history = db.session.scalars(
            db.select(FindingImport).filter_by(engagement_id=selected.id).order_by(FindingImport.id.desc()).limit(50)
        ).all()
    return render_template(
        "findings/imports.html", engagements=engagements, selected=selected, form=form, history=history,
        formats=parsers.FORMATS, confirmation=UPLOAD_CONFIRMATION,
        max_megabytes=current_app.config["IMPORT_MAX_BYTES"] // (1024 * 1024),
    )


def _handle_upload(engagement: Engagement | None):
    upload = request.files.get("report")
    if engagement is None:
        flash("Choose an engagement first.", "danger")
    elif request.form.get("confirm") != "y":
        flash("Confirm that these results are covered by the engagement's authorization.", "danger")
    elif upload is None or not upload.filename:
        flash("Choose a results file to upload.", "danger")
    else:
        data = upload.read(current_app.config["IMPORT_MAX_BYTES"] + 1)
        try:
            record = service.import_results(
                engagement, current_user, upload.filename, data, request.form.get("format", "auto")
            )
        except service.FindingError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            db.session.commit()
            flash(
                f"Imported {record.created_count} new findings. All stay unverified until a tester validates them.",
                "success",
            )
            return redirect(url_for("findings.imports", engagement=engagement.id))
    return None


@findings_bp.errorhandler(RequestEntityTooLarge)
def report_too_large(_error):
    flash(f"Reports are limited to {current_app.config['IMPORT_MAX_BYTES'] // (1024 * 1024)} MB.", "danger")
    return redirect(url_for("findings.imports"))


@findings_bp.route("/imports/template.json")
@permission_required("findings.view")
def import_template():
    return Response(
        json.dumps(GENERIC_TEMPLATE, indent=2), mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=sentinel-results-template.json"},
    )


@findings_bp.route("/new", methods=["GET", "POST"])
@permission_required("findings.manage")
def finding_new():
    engagements = [item for item in _visible_engagements() if item.is_authorized and item.status != "archived"]
    selected = _selected(engagements)
    form = ActionForm()
    if form.validate_on_submit():
        if selected is None:
            abort(404)
        try:
            row = service.create_manual_finding(selected, current_user, request.form.to_dict())
        except service.FindingError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            db.session.commit()
            flash("Finding recorded. Add evidence to confirm it.", "success")
            return redirect(url_for("findings.finding_detail", finding_id=row.id))
    return render_template(
        "findings/new.html", engagements=engagements, selected=selected, form=form, severities=Severity.ALL,
        values=request.form,
    )


@findings_bp.route("/<int:finding_id>")
@permission_required("findings.view")
def finding_detail(finding_id: int):
    row = _finding_or_404(finding_id)
    from app.models import RemediationStatus
    from app.reference import cwe as cwe_reference
    from app.reporting.remediation import RETEST_RESULTS, RETESTABLE_STATUSES
    cwe_reference.ensure_cwe()
    return render_template(
        "findings/detail.html", row=row, form=ActionForm(), severities=Severity.ALL,
        type_label=taxonomy.type_label(row.vulnerability_type),
        next_statuses=sorted(service.TRANSITIONS.get(row.validation_status, set())),
        tester_evidence=service.tester_evidence_count(row),
        can_view_evidence=current_user.has_permission("evidence.view"),
        remediation_statuses=RemediationStatus.ALL, retest_results=RETEST_RESULTS,
        can_retest=row.validation_status in RETESTABLE_STATUSES,
        cwe=cwe_reference.cwe_for(row.cwe_id),
    )


@findings_bp.route("/<int:finding_id>/validate", methods=["POST"])
@permission_required("findings.validate")
def finding_validate(finding_id: int):
    row = _finding_or_404(finding_id)
    if ActionForm().validate_on_submit():
        try:
            service.transition(row, current_user, request.form.get("status", ""), request.form.get("justification", ""))
        except service.FindingError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            db.session.commit()
            flash("Validation status updated.", "success")
    return redirect(url_for("findings.finding_detail", finding_id=finding_id))


@findings_bp.route("/<int:finding_id>/evidence", methods=["POST"])
@permission_required("evidence.manage")
def finding_evidence(finding_id: int):
    row = _finding_or_404(finding_id)
    if ActionForm().validate_on_submit():
        try:
            service.add_evidence(
                row, current_user, request.form.get("evidence_type", ""), request.form.get("title", ""),
                request.form.get("content", ""),
            )
        except service.FindingError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            db.session.commit()
            flash("Evidence added. Secrets were masked automatically.", "success")
    return redirect(url_for("findings.finding_detail", finding_id=finding_id))


@findings_bp.route("/<int:finding_id>/edit", methods=["POST"])
@permission_required("findings.manage")
def finding_edit(finding_id: int):
    row = _finding_or_404(finding_id)
    if ActionForm().validate_on_submit():
        try:
            service.update_details(row, current_user, request.form.to_dict())
        except service.FindingError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            db.session.commit()
            flash("Finding updated.", "success")
    return redirect(url_for("findings.finding_detail", finding_id=finding_id))
