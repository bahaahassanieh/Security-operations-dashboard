"""Manual Testing workspace. Every action here is performed by the tester, not the platform."""
from __future__ import annotations

import json

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user
from flask_wtf import FlaskForm
from sqlalchemy import func

from app.extensions import db
from app.findings import service as findings
from app.findings.service import FindingError
from app.manual import analyzers, service
from app.manual.playbooks import PLAYBOOKS
from app.models import (
    AuthzCheck,
    AuthzSubject,
    Engagement,
    ManualWorkflow,
    Severity,
    Vulnerability,
    WorkflowStep,
)
from app.models.manual import AUTHZ_EXPECTED, AUTHZ_OBSERVED, STEP_OUTCOMES
from app.services import engagements as engagement_service
from app.services.authz import permission_required

manual_bp = Blueprint("manual", __name__, url_prefix="/manual")


class ActionForm(FlaskForm):
    """Carries the CSRF token for forms whose fields are read directly."""


def _engagements() -> list[Engagement]:
    query = engagement_service.visible_engagements_query(current_user)
    return db.session.scalars(query.order_by(Engagement.created_at.desc())).all()


def _selected(engagements: list[Engagement]) -> Engagement | None:
    selected_id = request.values.get("engagement", type=int)
    if selected_id is None:
        return engagements[0] if engagements else None
    selected = next((item for item in engagements if item.id == selected_id), None)
    if selected is None:
        abort(404)
    return selected


def _visible(engagement_id: int) -> Engagement:
    engagement = engagement_service.get_visible_engagement(current_user, engagement_id)
    if engagement is None:
        abort(404)
    return engagement


def _workflow_or_404(workflow_id: int) -> ManualWorkflow:
    workflow = db.session.get(ManualWorkflow, workflow_id)
    if workflow is None:
        abort(404)
    _visible(workflow.engagement_id)
    return workflow


def _apply(action, success: str) -> bool:
    """Run a service call, commit on success and report the result to the tester."""
    try:
        action()
    except FindingError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
        return False
    db.session.commit()
    flash(success, "success")
    return True


@manual_bp.route("/")
@permission_required("engagement.view")
def index():
    engagements = _engagements()
    selected = _selected(engagements)
    workflows, summary = [], {}
    if selected is not None:
        workflows = db.session.scalars(
            db.select(ManualWorkflow).filter_by(engagement_id=selected.id).order_by(ManualWorkflow.id.desc())
        ).all()
        counts = dict(
            db.session.execute(
                db.select(ManualWorkflow.status, func.count()).filter_by(engagement_id=selected.id).group_by(ManualWorkflow.status)
            ).all()
        )
        summary = {"total": sum(counts.values()), "failed": counts.get("failed", 0), "passed": counts.get("passed", 0),
                   "violations": service.matrix_data(selected)["violations"]}
    return render_template(
        "manual/index.html", engagements=engagements, selected=selected, workflows=workflows, summary=summary,
        playbooks=PLAYBOOKS, form=ActionForm(), tab="workflows",
    )


@manual_bp.route("/workflows", methods=["POST"])
@permission_required("findings.manage")
def workflow_create():
    engagement = _visible(request.form.get("engagement", type=int) or 0)
    if ActionForm().validate_on_submit():
        created = {}

        def create():
            created["row"] = service.create_workflow(
                engagement, current_user, request.form.get("template", ""), request.form.get("title", ""),
                request.form.get("target_url", ""), request.form.get("objective", ""),
                test_data_confirmed=request.form.get("confirm") == "y",
            )

        if _apply(create, "Workflow created."):
            return redirect(url_for("manual.workflow_detail", workflow_id=created["row"].id))
    return redirect(url_for("manual.index", engagement=engagement.id))


@manual_bp.route("/workflows/<int:workflow_id>")
@permission_required("engagement.view")
def workflow_detail(workflow_id: int):
    workflow = _workflow_or_404(workflow_id)
    return render_template(
        "manual/workflow.html", workflow=workflow, form=ActionForm(), outcomes=STEP_OUTCOMES, severities=Severity.ALL
    )


@manual_bp.route("/workflows/<int:workflow_id>/steps", methods=["POST"])
@permission_required("findings.manage")
def step_add(workflow_id: int):
    workflow = _workflow_or_404(workflow_id)
    if ActionForm().validate_on_submit():
        _apply(lambda: service.add_step(workflow, current_user, request.form.get("action", ""), request.form.get("expected", "")), "Step added.")
    return redirect(url_for("manual.workflow_detail", workflow_id=workflow_id))


@manual_bp.route("/steps/<int:step_id>", methods=["POST"])
@permission_required("findings.manage")
def step_record(step_id: int):
    step = db.session.get(WorkflowStep, step_id)
    if step is None:
        abort(404)
    _visible(step.workflow.engagement_id)
    workflow_id = step.workflow_id
    if ActionForm().validate_on_submit():
        _apply(
            lambda: service.record_step(step, current_user, request.form.get("outcome", ""), request.form.get("actual", ""), request.form.get("evidence", "")),
            "Step recorded.",
        )
    return redirect(url_for("manual.workflow_detail", workflow_id=workflow_id))


@manual_bp.route("/workflows/<int:workflow_id>/finding", methods=["POST"])
@permission_required("findings.manage")
def workflow_finding(workflow_id: int):
    workflow = _workflow_or_404(workflow_id)
    if ActionForm().validate_on_submit():
        _apply(lambda: service.raise_workflow_finding(workflow, current_user, request.form.get("severity", "medium")), "Finding raised. It still needs validation.")
    return redirect(url_for("manual.workflow_detail", workflow_id=workflow_id))


@manual_bp.route("/authorization")
@permission_required("engagement.view")
def authorization():
    engagements = _engagements()
    selected = _selected(engagements)
    return render_template(
        "manual/authorization.html", engagements=engagements, selected=selected, form=ActionForm(), tab="authorization",
        matrix=service.matrix_data(selected) if selected else None, expected=AUTHZ_EXPECTED, observed=AUTHZ_OBSERVED,
        severities=Severity.ALL,
    )


@manual_bp.route("/authorization/subjects", methods=["POST"])
@permission_required("findings.manage")
def subject_add():
    engagement = _visible(request.form.get("engagement", type=int) or 0)
    if ActionForm().validate_on_submit():
        _apply(lambda: service.add_subject(engagement, current_user, request.form.get("label", ""), request.form.get("role", ""), request.form.get("reference", "")), "Test account added.")
    return redirect(url_for("manual.authorization", engagement=engagement.id))


@manual_bp.route("/authorization/checks", methods=["POST"])
@permission_required("findings.manage")
def check_add():
    engagement = _visible(request.form.get("engagement", type=int) or 0)
    if ActionForm().validate_on_submit():
        _apply(lambda: service.add_check(engagement, current_user, request.form.get("method", "GET"), request.form.get("url", ""), request.form.get("description", "")), "Resource added.")
    return redirect(url_for("manual.authorization", engagement=engagement.id))


@manual_bp.route("/authorization/checks/<int:check_id>/subjects/<int:subject_id>", methods=["POST"])
@permission_required("findings.manage")
def result_record(check_id: int, subject_id: int):
    check, subject = db.session.get(AuthzCheck, check_id), db.session.get(AuthzSubject, subject_id)
    if check is None or subject is None:
        abort(404)
    engagement = _visible(check.engagement_id)
    if ActionForm().validate_on_submit():
        _apply(lambda: service.record_result(check, subject, current_user, request.form.get("expected", ""), request.form.get("observed", ""), request.form.get("notes", "")), "Result recorded.")
    return redirect(url_for("manual.authorization", engagement=engagement.id))


@manual_bp.route("/authorization/checks/<int:check_id>/finding", methods=["POST"])
@permission_required("findings.manage")
def check_finding(check_id: int):
    check = db.session.get(AuthzCheck, check_id)
    if check is None:
        abort(404)
    engagement = _visible(check.engagement_id)
    if ActionForm().validate_on_submit():
        _apply(lambda: service.raise_authz_finding(check, current_user, request.form.get("severity", "high")), "Finding raised. It still needs validation.")
    return redirect(url_for("manual.authorization", engagement=engagement.id))


def _analysis_report(tool: str, result: dict) -> str:
    """Summarize a result for evidence. Raw tokens and pasted input are never included."""
    if tool == "compare":
        lines = [result["indicator"], f"Status: {result['status_a'] or 'none'} / {result['status_b'] or 'none'}",
                 f"Body similarity: {result['similarity']}%", "", *result["diff"]]
        return "\n".join(lines)
    return json.dumps(result, indent=2)


@manual_bp.route("/analyzers", methods=["GET", "POST"])
@permission_required("findings.manage")
def analyzers_page():
    engagements = _engagements()
    selected = _selected(engagements)
    tool = request.values.get("tool", "headers")
    tool = tool if tool in ("headers", "jwt", "compare") else "headers"
    form = ActionForm()
    result = None
    if form.validate_on_submit():
        try:
            if tool == "jwt":
                result = analyzers.analyze_jwt(request.form.get("token", ""))
            elif tool == "headers":
                result = analyzers.analyze_headers(request.form.get("headers", ""))
            else:
                result = analyzers.compare_responses(request.form.get("first", ""), request.form.get("second", ""))
        except analyzers.AnalyzerError as exc:
            flash(str(exc), "danger")
        finding_id = request.form.get("finding", type=int)
        if result is not None and finding_id:
            row = db.session.get(Vulnerability, finding_id)
            if row is None or selected is None or row.engagement_id != selected.id:
                abort(404)
            if not current_user.has_permission("evidence.manage"):
                abort(403)
            title = {"jwt": "Token review", "headers": "Response header review", "compare": "Response comparison"}[tool]
            _apply(lambda: findings.add_evidence(row, current_user, "comparison", title, _analysis_report(tool, result)), "Analysis attached to the finding.")
    available = []
    if selected is not None:
        available = db.session.scalars(
            db.select(Vulnerability).filter_by(engagement_id=selected.id).order_by(Vulnerability.id.desc()).limit(200)
        ).all()
    return render_template(
        "manual/analyzers.html", engagements=engagements, selected=selected, tool=tool, form=form, result=result,
        available=available, tab="analyzers",
    )


@manual_bp.route("/passive", methods=["GET", "POST"])
@permission_required("engagement.view")
def passive():
    engagements = _engagements()
    selected = _selected(engagements)
    form = ActionForm()
    if request.method == "POST":
        if not current_user.has_permission("findings.manage"):
            abort(403)
        if selected is None:
            abort(404)
        if form.validate_on_submit():
            outcome = {}

            def run():
                outcome["counters"] = service.run_passive_review(selected, current_user)

            if _apply(run, "Passive review finished."):
                counters = outcome["counters"]
                flash(f"{counters.created_count} new candidates, {counters.merged_count} correlated, {counters.duplicate_count} unchanged.", "info")
            return redirect(url_for("manual.passive", engagement=selected.id))
    return render_template("manual/passive.html", engagements=engagements, selected=selected, form=form, tab="passive")
