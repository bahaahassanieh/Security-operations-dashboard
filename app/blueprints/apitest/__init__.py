"""API Testing: review the mapped API inventory against the OWASP API Security Top 10."""
from __future__ import annotations

import re
from collections import Counter

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user
from flask_wtf import FlaskForm
from sqlalchemy import or_

from app.extensions import db
from app.methodology import api_top10
from app.methodology import library as methodology
from app.models import Endpoint, EndpointParameter, Engagement, TestCase, TestExecution
from app.models.testing import EXECUTION_STATUSES
from app.services import engagements as engagement_service
from app.services.authz import permission_required

apitest_bp = Blueprint("apitest", __name__, url_prefix="/api-testing")
_SOAP = re.compile(r"\.asmx|wsdl|/soap(/|$)", re.I)
_WEBSOCKET = re.compile(r"/(ws|wss|websocket|socket\.io|sockjs)(/|$)", re.I)


class ActionForm(FlaskForm):
    """Carries the CSRF token for checklist updates."""


def api_style(endpoint: Endpoint) -> str:
    """Identify an API route's technology from what was observed."""
    location = f"{endpoint.path}?{endpoint.url.partition('?')[2]}"
    if endpoint.category == "graphql":
        return "GraphQL"
    if _WEBSOCKET.search(endpoint.path or ""):
        return "WebSocket"
    if _SOAP.search(location) or "soap" in (endpoint.content_type or ""):
        return "SOAP"
    return "REST"


@apitest_bp.route("/")
@permission_required("engagement.view")
def index():
    methodology.ensure_library()
    query = engagement_service.visible_engagements_query(current_user)
    engagements = db.session.scalars(query.order_by(Engagement.created_at.desc())).all()
    selected_id = request.args.get("engagement", type=int)
    if selected_id is None and engagements:
        selected_id = engagements[0].id
    selected = next((item for item in engagements if item.id == selected_id), None)
    if selected_id is not None and selected is None:
        abort(404)
    routes, styles, parameters, executions, unprotected = [], Counter(), {}, {}, 0
    cases = db.session.scalars(
        db.select(TestCase).filter_by(category=api_top10.CATEGORY).order_by(TestCase.id)
    ).all()
    if selected is not None:
        routes = db.session.scalars(
            db.select(Endpoint)
            .filter_by(engagement_id=selected.id, in_scope=True)
            .where(or_(Endpoint.category.in_(("api", "graphql")), Endpoint.path.regexp_match(r"/(ws|websocket|socket\.io|sockjs)(/|$)")))
            .order_by(Endpoint.url, Endpoint.method)
            .limit(500)
        ).all()
        styles = Counter(api_style(item) for item in routes)
        unprotected = sum(item.requires_auth is False for item in routes)
        parameters = Counter(
            db.session.scalars(
                db.select(EndpointParameter.endpoint_id).where(EndpointParameter.endpoint_id.in_([item.id for item in routes]))
            ).all()
        )
        executions = {
            item.test_case_id: item
            for item in db.session.scalars(db.select(TestExecution).filter_by(engagement_id=selected.id))
        }
    reviewed = sum(1 for case in cases if case.id in executions and executions[case.id].status in methodology.COMPLETE_STATUSES)
    return render_template(
        "apitest/index.html", engagements=engagements, selected=selected, routes=routes, styles=styles,
        parameters=parameters, executions=executions, cases=cases, statuses=EXECUTION_STATUSES, reviewed=reviewed,
        unprotected=unprotected, api_style=api_style, form=ActionForm(),
    )


@apitest_bp.route("/engagements/<int:engagement_id>/cases/<int:case_id>", methods=["POST"])
@permission_required("findings.manage")
def update(engagement_id: int, case_id: int):
    engagement = engagement_service.get_visible_engagement(current_user, engagement_id)
    case = db.session.get(TestCase, case_id)
    if engagement is None or case is None or case.category != api_top10.CATEGORY:
        abort(404)
    if ActionForm().validate_on_submit():
        try:
            methodology.update_execution(engagement, case, current_user, request.form.get("status", ""), request.form.get("notes", ""))
        except methodology.MethodologyError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            db.session.commit()
            flash(f"{case.framework_reference} updated.", "success")
    return redirect(url_for("apitest.index", engagement=engagement.id))
