"""Evidence repository: browse, upload, download and delete evidence."""
from __future__ import annotations

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, send_file, url_for
from flask_login import current_user
from flask_wtf import FlaskForm
from werkzeug.exceptions import RequestEntityTooLarge

from app.extensions import db
from app.findings.service import FindingError
from app.models import Engagement, Evidence, Vulnerability
from app.reporting import evidence as evidence_service
from app.services import engagements as engagement_service
from app.services.authz import permission_required

evidence_bp = Blueprint("evidence", __name__, url_prefix="/evidence")


class ActionForm(FlaskForm):
    """Carries the CSRF token for evidence actions."""


@evidence_bp.url_value_preprocessor
def raise_upload_limit(endpoint, _values):
    if endpoint == "evidence.upload" and request.method == "POST":
        request.max_content_length = current_app.config["EVIDENCE_MAX_BYTES"] + 64 * 1024


@evidence_bp.errorhandler(RequestEntityTooLarge)
def too_large(_error):
    flash(f"Evidence files are limited to {current_app.config['EVIDENCE_MAX_BYTES'] // (1024 * 1024)} MB.", "danger")
    return redirect(request.referrer or url_for("evidence.index"))


def _engagements():
    return db.session.scalars(
        engagement_service.visible_engagements_query(current_user).order_by(Engagement.created_at.desc())
    ).all()


def _finding_or_404(finding_id: int) -> Vulnerability:
    row = db.session.get(Vulnerability, finding_id)
    if row is None or engagement_service.get_visible_engagement(current_user, row.engagement_id) is None:
        abort(404)
    return row


def _evidence_or_404(evidence_id: int) -> Evidence:
    item = db.session.get(Evidence, evidence_id)
    if item is None or engagement_service.get_visible_engagement(current_user, item.engagement_id) is None:
        abort(404)
    return item


@evidence_bp.route("/")
@permission_required("evidence.view")
def index():
    engagements = _engagements()
    selected_id = request.args.get("engagement", type=int)
    if selected_id is None and engagements:
        selected_id = engagements[0].id
    selected = next((item for item in engagements if item.id == selected_id), None)
    if selected_id is not None and selected is None:
        abort(404)
    items = evidence_service.engagement_evidence(selected) if selected else []
    return render_template("evidence/index.html", engagements=engagements, selected=selected, items=items, form=ActionForm())


@evidence_bp.route("/findings/<int:finding_id>/upload", methods=["POST"])
@permission_required("evidence.manage")
def upload(finding_id: int):
    finding = _finding_or_404(finding_id)
    if ActionForm().validate_on_submit():
        upload = request.files.get("file")
        if upload is None or not upload.filename:
            flash("Choose a file to upload.", "danger")
        else:
            data = upload.read(current_app.config["EVIDENCE_MAX_BYTES"] + 1)
            try:
                evidence_service.add_file_evidence(finding, current_user, request.form.get("title", ""), upload.filename, data)
            except FindingError as exc:
                db.session.rollback()
                flash(str(exc), "danger")
            else:
                db.session.commit()
                flash("Evidence uploaded. Secrets in text files were masked.", "success")
    return redirect(url_for("findings.finding_detail", finding_id=finding_id))


@evidence_bp.route("/<int:evidence_id>/file")
@permission_required("evidence.view")
def download(evidence_id: int):
    item = _evidence_or_404(evidence_id)
    try:
        path = evidence_service.evidence_file_path(item)
    except FindingError:
        abort(404)
    # Served as an attachment with its stored type; never inline, so a crafted file cannot run in the browser.
    return send_file(path, mimetype=item.mime_type or "application/octet-stream", as_attachment=True,
                     download_name=item.original_filename or f"evidence-{item.id}")


@evidence_bp.route("/<int:evidence_id>/delete", methods=["POST"])
@permission_required("evidence.manage")
def delete(evidence_id: int):
    item = _evidence_or_404(evidence_id)
    finding_id = item.vulnerability_id
    if ActionForm().validate_on_submit():
        try:
            evidence_service.delete_evidence(item, current_user)
        except FindingError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            db.session.commit()
            flash("Evidence deleted.", "success")
    if finding_id:
        return redirect(url_for("findings.finding_detail", finding_id=finding_id))
    return redirect(url_for("evidence.index"))
