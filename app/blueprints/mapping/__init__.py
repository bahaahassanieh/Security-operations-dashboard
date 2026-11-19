"""Application Mapping: start crawls and inspect the endpoint inventory and its relationships."""
from __future__ import annotations

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user
from flask_wtf import FlaskForm
from sqlalchemy import func, or_
from wtforms import BooleanField
from wtforms.validators import DataRequired

from app.extensions import db
from app.models import (
    Endpoint,
    EndpointLink,
    EndpointParameter,
    Engagement,
    EngagementStatus,
    WebCookie,
    WebForm,
)
from app.models.mapping import CRAWL_STATES
from app.services import engagements as engagement_service
from app.services import jobs, settings
from app.services.authz import permission_required

mapping_bp = Blueprint("mapping", __name__, url_prefix="/mapping")

CONFIRMATION = (
    "I confirm this crawl is covered by the recorded client authorization and may send requests "
    "to the in-scope targets now."
)
TABS = {
    "endpoints": "Endpoints",
    "structure": "Site structure",
    "forms": "Forms",
    "parameters": "Parameters",
    "cookies": "Cookies",
}
_TREE_LIMIT = 2000


class StartForm(FlaskForm):
    confirm = BooleanField(CONFIRMATION, validators=[DataRequired()])


def _engagement_or_404(engagement_id: int) -> Engagement:
    engagement = engagement_service.get_visible_engagement(current_user, engagement_id)
    if engagement is None:
        abort(404)
    return engagement


def _like(value: str) -> str:
    return "%" + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def build_site_tree(endpoints: list[Endpoint]) -> list[dict]:
    """Group endpoints into a tree of origins and path segments."""
    roots: dict[str, dict] = {}
    for endpoint in endpoints:
        scheme, _, remainder = endpoint.url.partition("://")
        origin = f"{scheme}://{remainder.split('/', 1)[0]}"
        node = roots.setdefault(origin, {"name": origin, "children": {}, "endpoints": []})
        for segment in [part for part in (endpoint.path or "/").split("/") if part][:12]:
            node = node["children"].setdefault(segment, {"name": segment, "children": {}, "endpoints": []})
        node["endpoints"].append(endpoint)

    def freeze(node: dict) -> dict:
        return {
            "name": node["name"],
            "endpoints": node["endpoints"],
            "children": [freeze(child) for _, child in sorted(node["children"].items())],
        }

    return [freeze(node) for _, node in sorted(roots.items())]


@mapping_bp.route("/")
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

    tab = request.args.get("tab", "endpoints")
    tab = tab if tab in TABS else "endpoints"
    filters = {
        "category": request.args.get("category", "")[:32],
        "state": request.args.get("state", ""),
        "method": request.args.get("method", "")[:10].upper(),
        "auth": request.args.get("auth", ""),
        "q": request.args.get("q", "").strip()[:100],
    }
    context = {"page": None, "tree": [], "categories": [], "summary": {}}
    if selected is not None:
        base = db.select(Endpoint).filter_by(engagement_id=selected.id)
        context["categories"] = db.session.scalars(
            db.select(Endpoint.category).filter_by(engagement_id=selected.id).distinct().order_by(Endpoint.category)
        ).all()
        count = lambda model, *criteria: db.session.scalar(  # noqa: E731
            db.select(func.count()).select_from(model).filter_by(engagement_id=selected.id).where(*criteria)
        )
        context["summary"] = {
            "endpoints": count(Endpoint),
            "fetched": count(Endpoint, Endpoint.crawl_state == "fetched"),
            "protected": count(Endpoint, Endpoint.requires_auth.is_(True)),
            "api": count(Endpoint, Endpoint.category.in_(("api", "graphql"))),
            "forms": count(WebForm),
            "parameters": count(EndpointParameter),
            "cookies": count(WebCookie),
        }
        if tab == "endpoints":
            rows = base
            if filters["category"]:
                rows = rows.where(Endpoint.category == filters["category"])
            if filters["state"] in CRAWL_STATES:
                rows = rows.where(Endpoint.crawl_state == filters["state"])
            if filters["method"]:
                rows = rows.where(Endpoint.method == filters["method"])
            if filters["auth"] == "yes":
                rows = rows.where(Endpoint.requires_auth.is_(True))
            if filters["q"]:
                rows = rows.where(Endpoint.url.ilike(_like(filters["q"]), escape="\\"))
            context["page"] = db.paginate(rows.order_by(Endpoint.url, Endpoint.method), per_page=50, error_out=False)
        elif tab == "structure":
            context["tree"] = build_site_tree(
                db.session.scalars(
                    base.where(Endpoint.in_scope.is_(True)).order_by(Endpoint.url).limit(_TREE_LIMIT)
                ).all()
            )
        elif tab == "forms":
            context["page"] = db.paginate(
                db.select(WebForm).filter_by(engagement_id=selected.id).order_by(WebForm.id),
                per_page=50, error_out=False,
            )
        elif tab == "parameters":
            rows = db.select(EndpointParameter).filter_by(engagement_id=selected.id)
            if filters["q"]:
                rows = rows.where(EndpointParameter.name.ilike(_like(filters["q"]), escape="\\"))
            context["page"] = db.paginate(
                rows.order_by(EndpointParameter.name, EndpointParameter.id), per_page=50, error_out=False
            )
        else:
            context["page"] = db.paginate(
                db.select(WebCookie).filter_by(engagement_id=selected.id).order_by(WebCookie.host, WebCookie.name),
                per_page=50, error_out=False,
            )
    return render_template(
        "mapping/index.html", engagements=engagements, selected=selected, tab=tab, tabs=TABS,
        filters=filters, states=CRAWL_STATES, worker_online=jobs.worker_online(), **context,
    )


@mapping_bp.route("/engagements/<int:engagement_id>/new", methods=["GET", "POST"])
@permission_required("assessment.execute")
def new_job(engagement_id: int):
    engagement = _engagement_or_404(engagement_id)
    form = StartForm()
    limits = {key: settings.DEFINITIONS[key] for key in ("mapping.max_depth", "mapping.max_pages")}
    if form.validate_on_submit():
        options = {
            "max_depth": request.form.get("max_depth", type=int),
            "max_pages": request.form.get("max_pages", type=int),
            "respect_robots": request.form.get("respect_robots") == "y",
        }
        try:
            job = jobs.create_mapping_job(engagement, current_user, request.form.getlist("modules"), options)
        except jobs.JobError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            db.session.commit()
            return redirect(url_for("recon.job_detail", job_id=job.id))
    elif request.method == "POST":
        flash("Tick the confirmation before starting.", "danger")
    return render_template(
        "mapping/new.html", engagement=engagement, form=form, limits=limits,
        modules=jobs.available_modules(engagement, jobs.MAPPING_MODULES),
        defaults={key: settings.get_int(key) for key in limits},
        rate=settings.get_int("recon.rate_limit_rps"),
        active=engagement.status == EngagementStatus.ACTIVE,
        worker_online=jobs.worker_online(),
    )


@mapping_bp.route("/endpoints/<int:endpoint_id>")
@permission_required("engagement.view")
def endpoint_detail(endpoint_id: int):
    endpoint = db.session.get(Endpoint, endpoint_id)
    if endpoint is None or engagement_service.get_visible_engagement(current_user, endpoint.engagement_id) is None:
        abort(404)
    inbound = db.session.scalars(
        db.select(EndpointLink).filter_by(target_id=endpoint.id).order_by(EndpointLink.id).limit(200)
    ).all()
    outbound = db.session.scalars(
        db.select(EndpointLink).filter_by(source_id=endpoint.id).order_by(EndpointLink.id).limit(200)
    ).all()
    parameters = db.session.scalars(
        db.select(EndpointParameter).filter_by(endpoint_id=endpoint.id).order_by(EndpointParameter.name)
    ).all()
    forms = db.session.scalars(
        db.select(WebForm).where(or_(WebForm.page_id == endpoint.id, WebForm.action_id == endpoint.id))
    ).all()
    return render_template(
        "mapping/endpoint.html", endpoint=endpoint, inbound=inbound, outbound=outbound,
        parameters=parameters, forms=forms,
    )
