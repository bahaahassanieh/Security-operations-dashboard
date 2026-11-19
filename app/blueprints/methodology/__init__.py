"""Testing methodology progress and the test case library."""
from __future__ import annotations

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user
from flask_wtf import FlaskForm
from sqlalchemy import or_

from app.extensions import db
from app.findings import service as findings_service
from app.findings.service import FindingError
from app.methodology import library as service
from app.methodology import api_top10, wstg
from app.reference import cwe as cwe_reference
from app.models import Engagement, Severity, TestCase
from app.models.testing import EXECUTION_STATUSES
from app.services import engagements as engagement_service
from app.services.authz import permission_required

methodology_bp = Blueprint("methodology", __name__, url_prefix="/methodology")
LIBRARY_CATEGORIES = {
    **wstg.CATEGORIES, api_top10.CATEGORY: api_top10.CATEGORY_LABEL,
    cwe_reference.CWE_CATEGORY: cwe_reference.CWE_CATEGORY_LABEL,
}


class ActionForm(FlaskForm):
    """Carries the CSRF token for status updates."""


@methodology_bp.route("/")
@permission_required("engagement.view")
def progress():
    service.ensure_library()
    query = engagement_service.visible_engagements_query(current_user)
    engagements = db.session.scalars(query.order_by(Engagement.created_at.desc())).all()
    selected_id = request.args.get("engagement", type=int)
    if selected_id is None and engagements:
        selected_id = engagements[0].id
    selected = next((item for item in engagements if item.id == selected_id), None)
    if selected_id is not None and selected is None:
        abort(404)
    category = request.args.get("category", "INFO")
    category = category if category in wstg.CATEGORIES else "INFO"
    summary, cases, linked = None, [], {}
    if selected is not None:
        summary = service.engagement_progress(selected)
        linked = service.findings_per_case(selected.id)
        cases = db.session.scalars(
            db.select(TestCase).filter_by(category=category, is_active=True).order_by(TestCase.test_id)
        ).all()
    return render_template(
        "methodology/progress.html", engagements=engagements, selected=selected, summary=summary, cases=cases,
        category=category, categories=wstg.CATEGORIES, statuses=EXECUTION_STATUSES, linked=linked, form=ActionForm(),
    )


@methodology_bp.route("/engagements/<int:engagement_id>/cases/<int:case_id>", methods=["POST"])
@permission_required("findings.manage")
def progress_update(engagement_id: int, case_id: int):
    engagement = engagement_service.get_visible_engagement(current_user, engagement_id)
    case = db.session.get(TestCase, case_id)
    if engagement is None or case is None:
        abort(404)
    if ActionForm().validate_on_submit():
        try:
            service.update_execution(
                engagement, case, current_user, request.form.get("status", ""), request.form.get("notes", "")
            )
        except service.MethodologyError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            db.session.commit()
            flash(f"{case.test_id} updated.", "success")
    return redirect(url_for("methodology.progress", engagement=engagement.id, category=case.category))


@methodology_bp.route("/library")
@permission_required("engagement.view")
def library():
    service.ensure_library()
    cwe_reference.ensure_cwe()
    category = request.args.get("category", "")
    search = request.args.get("q", "").strip()[:100]
    query = db.select(TestCase).filter_by(is_active=True)
    if category in LIBRARY_CATEGORIES:
        query = query.filter_by(category=category)
    if search:
        pattern = "%" + search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        query = query.where(
            or_(TestCase.title.ilike(pattern, escape="\\"), TestCase.test_id.ilike(pattern, escape="\\"))
        )
    page = db.paginate(query.order_by(TestCase.test_id), per_page=50, error_out=False)
    return render_template(
        "methodology/library.html", page=page, category=category, search=search, categories=LIBRARY_CATEGORIES
    )


@methodology_bp.route("/library/<int:case_id>")
@permission_required("engagement.view")
def library_case(case_id: int):
    case = db.session.get(TestCase, case_id)
    if case is None:
        abort(404)
    engagements = []
    if current_user.has_permission("findings.manage"):
        engagements = [
            item for item in db.session.scalars(
                engagement_service.visible_engagements_query(current_user).order_by(Engagement.created_at.desc())
            )
            if item.is_authorized and item.status != "archived"
        ]
    return render_template(
        "methodology/case.html", case=case, category=LIBRARY_CATEGORIES.get(case.category, case.category),
        engagements=engagements, severities=Severity.ALL, form=ActionForm(),
    )


@methodology_bp.route("/library/<int:case_id>/finding", methods=["POST"])
@permission_required("findings.manage")
def library_case_finding(case_id: int):
    case = db.session.get(TestCase, case_id)
    if case is None:
        abort(404)
    engagement = engagement_service.get_visible_engagement(current_user, request.form.get("engagement", type=int) or 0)
    if engagement is None:
        abort(404)
    if ActionForm().validate_on_submit():
        data = {
            "name": case.title, "severity": request.form.get("severity") or case.default_severity,
            "url": request.form.get("url", ""), "parameter": request.form.get("parameter", ""),
            "method": request.form.get("method", ""), "description": request.form.get("description", ""),
            "test_case_id": case.id,
        }
        try:
            row = findings_service.create_manual_finding(engagement, current_user, data)
        except FindingError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            db.session.commit()
            flash(f"Finding {row.finding_uid} created from {case.test_id}.", "success")
            return redirect(url_for("findings.finding_detail", finding_id=row.id))
    return redirect(url_for("methodology.library_case", case_id=case_id))
