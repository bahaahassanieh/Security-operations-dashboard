"""Reconnaissance: start jobs, monitor them and review tool output."""
from __future__ import annotations

from pathlib import Path

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import current_user
from flask_wtf import FlaskForm
from wtforms import BooleanField
from wtforms.validators import DataRequired

from app.extensions import db
from app.models import Engagement, EngagementStatus, ExecutionJob, ToolRun
from app.services import engagements as engagement_service
from app.services import jobs
from app.services.authz import permission_required

recon_bp = Blueprint("recon", __name__, url_prefix="/recon")

CONFIRMATION = (
    "I confirm this assessment is covered by the recorded client authorization and may send "
    "traffic to the in-scope targets now."
)


class StartForm(FlaskForm):
    confirm = BooleanField(CONFIRMATION, validators=[DataRequired()])


class ActionForm(FlaskForm):
    """Carries the CSRF token for job controls."""


def _engagement_or_404(engagement_id: int) -> Engagement:
    engagement = engagement_service.get_visible_engagement(current_user, engagement_id)
    if engagement is None:
        abort(404)
    return engagement


def job_or_404(job_id: int) -> ExecutionJob:
    """Load a job only if the user may access its engagement."""
    job = db.session.get(ExecutionJob, job_id)
    if job is None or engagement_service.get_visible_engagement(current_user, job.engagement_id) is None:
        abort(404)
    return job


@recon_bp.route("/")
@permission_required("engagement.view")
def index():
    query = engagement_service.visible_engagements_query(current_user)
    engagements = db.session.scalars(query.order_by(Engagement.created_at.desc())).all()
    ids = [engagement.id for engagement in engagements]
    recent = db.session.scalars(
        db.select(ExecutionJob)
        .where(ExecutionJob.engagement_id.in_(ids))
        .order_by(ExecutionJob.id.desc())
        .limit(25)
    ).all()
    return render_template(
        "recon/index.html",
        engagements=[item for item in engagements if item.status == EngagementStatus.ACTIVE],
        jobs=recent,
        worker_online=jobs.worker_online(),
    )


@recon_bp.route("/engagements/<int:engagement_id>/new", methods=["GET", "POST"])
@permission_required("assessment.execute")
def new_job(engagement_id: int):
    engagement = _engagement_or_404(engagement_id)
    form = StartForm()
    if form.validate_on_submit():
        try:
            job = jobs.create_recon_job(engagement, current_user, request.form.getlist("modules"))
        except jobs.JobError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            db.session.commit()
            return redirect(url_for("recon.job_detail", job_id=job.id))
    elif request.method == "POST":
        flash("Tick the confirmation before starting.", "danger")
    return render_template(
        "recon/new.html",
        engagement=engagement,
        form=form,
        modules=jobs.available_modules(engagement),
        failure=engagement_service.execution_precondition_failure(
            engagement, current_user, "manual_testing"
        )
        if engagement.status != EngagementStatus.ACTIVE
        else None,
        worker_online=jobs.worker_online(),
    )


@recon_bp.route("/engagements/<int:engagement_id>/assess", methods=["GET", "POST"])
@permission_required("assessment.execute")
def assess(engagement_id: int):
    engagement = _engagement_or_404(engagement_id)
    form = StartForm()
    plan = jobs.assessment_plan(engagement)
    if form.validate_on_submit():
        try:
            job = jobs.create_assessment_job(engagement, current_user, {})
        except jobs.JobError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            db.session.commit()
            return redirect(url_for("recon.job_detail", job_id=job.id))
    elif request.method == "POST":
        flash("Tick the confirmation before starting.", "danger")
    return render_template(
        "recon/assess.html", engagement=engagement, form=form,
        runnable=[item for item in plan if item["blocked_reason"] is None],
        blocked=[item for item in plan if item["blocked_reason"]],
        failure=engagement_service.execution_precondition_failure(engagement, current_user, "manual_testing")
        if engagement.status != EngagementStatus.ACTIVE else None,
        worker_online=jobs.worker_online(),
    )


@recon_bp.route("/jobs/<int:job_id>")
@permission_required("engagement.view")
def job_detail(job_id: int):
    job = job_or_404(job_id)
    return render_template(
        "recon/job.html", job=job, action_form=ActionForm(), worker_online=jobs.worker_online()
    )


@recon_bp.route("/jobs/<int:job_id>/control", methods=["POST"])
@permission_required("assessment.execute")
def control(job_id: int):
    job = job_or_404(job_id)
    if ActionForm().validate_on_submit():
        try:
            jobs.control_job(job, request.form.get("action", ""), current_user)
        except jobs.JobError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            db.session.commit()
    return redirect(url_for("recon.job_detail", job_id=job.id))


@recon_bp.route("/runs/<int:run_id>/output")
@permission_required("evidence.view")
def run_output(run_id: int):
    """Download a tool's raw output as an inert text attachment."""
    run = db.session.get(ToolRun, run_id)
    if run is None or not run.output_path:
        abort(404)
    job_or_404(run.job_id)
    root = Path(current_app.config["JOB_DIR"]).resolve()
    path = Path(run.output_path).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        abort(404)
    return send_file(
        path, mimetype="text/plain", as_attachment=True,
        download_name=f"job-{run.job_id}-run-{run.id}-{run.tool_name}.txt",
    )
