"""JSON REST API (v1). Uses the session cookie; writes require an X-CSRFToken header."""
from __future__ import annotations

from flask import Blueprint, abort, jsonify, request
from flask_login import current_user

from app.extensions import db
from app.models import Engagement, ExecutionJob, JobEvent, ToolRun
from app.services import dashboard
from app.services import engagements as service
from app.services.authz import permission_required

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")


def _serialize(engagement: Engagement, *, full: bool = False) -> dict:
    data = {
        "id": engagement.id,
        "name": engagement.name,
        "client_name": engagement.client_name,
        "status": engagement.status,
        "primary_target_url": engagement.primary_target_url,
        "start_date": engagement.start_date.isoformat(),
        "end_date": engagement.end_date.isoformat(),
        "authorized": service.authorization_is_current(engagement),
    }
    if full:
        data |= {
            "description": engagement.description,
            "rules_of_engagement": engagement.rules_of_engagement,
            "authorized_methods": engagement.authorized_methods,
            "scope": [
                {"type": entry.entry_type, "value": entry.value, "excluded": entry.is_exclusion}
                for entry in engagement.scope_entries
            ],
            "testers": [user.username for user in engagement.testers],
        }
    return data


def _engagement_or_404(engagement_id: int) -> Engagement:
    engagement = service.get_visible_engagement(current_user, engagement_id)
    if engagement is None:
        abort(404)
    return engagement


@api_bp.route("/dashboard/summary")
@permission_required()
def dashboard_summary():
    return jsonify(dashboard.build_summary(current_user))


@api_bp.route("/engagements")
@permission_required("engagement.view")
def list_engagements():
    query = service.visible_engagements_query(current_user).order_by(Engagement.id.desc())
    page = db.paginate(query, per_page=50, max_per_page=100, error_out=False)
    return jsonify(
        items=[_serialize(engagement) for engagement in page.items],
        page=page.page,
        pages=page.pages,
        total=page.total,
    )


@api_bp.route("/engagements/<int:engagement_id>")
@permission_required("engagement.view")
def get_engagement(engagement_id: int):
    return jsonify(_serialize(_engagement_or_404(engagement_id), full=True))


@api_bp.route("/jobs/<int:job_id>")
@permission_required("engagement.view")
def get_job(job_id: int):
    """Live job status for the monitoring page."""
    job = db.session.get(ExecutionJob, job_id)
    if job is None or service.get_visible_engagement(current_user, job.engagement_id) is None:
        abort(404)
    after = request.args.get("after", 0, type=int)
    events = job.events.filter(JobEvent.id > after).limit(200).all()
    return jsonify(
        id=job.id,
        status=job.status,
        progress=job.progress,
        pause_requested=job.pause_requested,
        cancel_requested=job.cancel_requested,
        events=[
            {
                "id": event.id,
                "time": event.created_at.strftime("%H:%M:%S"),
                "level": event.level,
                "module": event.module,
                "message": event.message,
            }
            for event in events
        ],
        tool_runs=[
            {
                "id": run.id,
                "tool": run.tool_name,
                "target": run.target,
                "status": run.status,
                "exit_code": run.exit_code,
                "duration_ms": run.duration_ms,
            }
            for run in job.tool_runs.order_by(ToolRun.id.desc()).limit(100)
        ],
    )


@api_bp.route("/engagements/<int:engagement_id>/scope-check", methods=["POST"])
@permission_required("scope.check")
def scope_check(engagement_id: int):
    engagement = _engagement_or_404(engagement_id)
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("target"), str):
        return jsonify(error="target_required"), 400
    decision = service.check_target(
        engagement, payload["target"][:2048], current_user, resolve=payload.get("resolve") is True
    )
    db.session.commit()
    return jsonify(decision.as_dict())
