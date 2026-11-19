"""Targets and assets inventory."""
from __future__ import annotations

from flask import Blueprint, abort, render_template, request
from flask_login import current_user
from sqlalchemy import func

from app.extensions import db
from app.models import Asset, Endpoint, Engagement, Subdomain, Technology
from app.services import engagements as engagement_service
from app.services.authz import permission_required

assets_bp = Blueprint("assets", __name__, url_prefix="/assets")

TABS = {
    "services": ("Services", Asset),
    "hosts": ("Hosts", Subdomain),
    "endpoints": ("Endpoints", Endpoint),
    "technologies": ("Technologies", Technology),
}


@assets_bp.route("/")
@permission_required("engagement.view")
def index():
    query = engagement_service.visible_engagements_query(current_user)
    engagements = db.session.scalars(query.order_by(Engagement.created_at.desc())).all()
    selected_id = request.args.get("engagement", type=int)
    if selected_id is None and engagements:
        selected_id = engagements[0].id
    selected = next((item for item in engagements if item.id == selected_id), None)
    if selected_id is not None and selected is None:
        abort(404)

    tab = request.args.get("tab", "services")
    tab = tab if tab in TABS else "services"
    scope = request.args.get("scope", "in")
    scope = scope if scope in ("in", "out", "all") else "in"

    page = None
    counts = {}
    if selected is not None:
        for name, (_, model) in TABS.items():
            counts[name] = db.session.scalar(
                db.select(func.count()).select_from(model).filter_by(engagement_id=selected.id)
            )
        model = TABS[tab][1]
        rows = db.select(model).filter_by(engagement_id=selected.id).order_by(model.id)
        if tab != "technologies" and scope != "all":
            rows = rows.filter_by(in_scope=scope == "in")
        page = db.paginate(rows, per_page=50, error_out=False)
    return render_template(
        "assets/index.html",
        engagements=engagements,
        selected=selected,
        tab=tab,
        tabs=TABS,
        scope=scope,
        page=page,
        counts=counts,
    )
