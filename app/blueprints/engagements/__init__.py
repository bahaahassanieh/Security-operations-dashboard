"""Engagement management routes."""
from __future__ import annotations

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user
from flask_wtf import FlaskForm
from sqlalchemy import or_
from wtforms import (
    BooleanField,
    DateField,
    HiddenField,
    SelectMultipleField,
    StringField,
    SubmitField,
    TextAreaField,
    URLField,
    widgets,
)
from wtforms.validators import DataRequired, Length, Optional

from app.extensions import db
from app.models import AuditOutcome, Engagement, EngagementStatus, User
from app.models.base import TESTING_METHODS
from app.services import audit
from app.services import engagements as service
from app.services.authz import permission_required

engagements_bp = Blueprint("engagements", __name__, url_prefix="/engagements")

AUTHORIZATION_STATEMENT = (
    "I confirm that the client has given written authorization to test the targets in this "
    "scope, during these dates, using the selected methods."
)


class MultiCheckboxField(SelectMultipleField):
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()


class EngagementForm(FlaskForm):
    name = StringField("Engagement name", validators=[DataRequired(), Length(max=160)])
    client_name = StringField("Client name", validators=[DataRequired(), Length(max=160)])
    description = TextAreaField("Description", validators=[Optional(), Length(max=5000)])
    primary_target_url = URLField(
        "Primary target URL", validators=[DataRequired(), Length(max=2048)]
    )
    start_date = DateField("Testing start date", validators=[DataRequired()])
    end_date = DateField("Testing end date", validators=[DataRequired()])
    authorized_scope = TextAreaField(
        "Authorized domains and IP ranges", validators=[DataRequired(), Length(max=20000)]
    )
    excluded_scope = TextAreaField("Excluded targets", validators=[Optional(), Length(max=20000)])
    rules_of_engagement = TextAreaField(
        "Rules of engagement", validators=[Optional(), Length(max=20000)]
    )
    authorized_methods = MultiCheckboxField(
        "Authorized testing methods", choices=list(TESTING_METHODS.items())
    )
    credential_references = TextAreaField(
        "Credential references", validators=[Optional(), Length(max=5000)]
    )
    tester_ids = MultiCheckboxField("Assigned testers", coerce=int)
    submit = SubmitField("Save engagement")


class AuthorizationForm(FlaskForm):
    authorization_reference = StringField(
        "Authorization document reference", validators=[DataRequired(), Length(max=255)]
    )
    authorization_signatory = StringField(
        "Client signatory", validators=[DataRequired(), Length(max=160)]
    )
    confirm = BooleanField(AUTHORIZATION_STATEMENT, validators=[DataRequired()])
    submit = SubmitField("Record authorization")


class StatusForm(FlaskForm):
    status = HiddenField(validators=[DataRequired()])


class ScopeCheckForm(FlaskForm):
    target = StringField("Target", validators=[DataRequired(), Length(max=2048)])
    resolve = BooleanField("Also resolve DNS (as at execution time)")
    submit = SubmitField("Check scope")


def _load_engagement(engagement_id: int) -> Engagement:
    """Fetch an engagement the user may access. Others get an audited 404."""
    engagement = service.get_visible_engagement(current_user, engagement_id)
    if engagement is None:
        audit.record(
            "authz.denied",
            outcome=AuditOutcome.DENIED,
            object_type="engagement",
            object_id=engagement_id,
            details={"reason": "not_assigned_or_missing"},
        )
        db.session.commit()
        abort(404)
    return engagement


def _tester_choices() -> list[tuple[int, str]]:
    users = db.session.scalars(
        db.select(User).filter_by(is_enabled=True).order_by(User.username)
    )
    return [(user.id, f"{user.display_name} ({user.role.name})") for user in users]


def _lines(text: str | None) -> list[str]:
    return [line.strip() for line in (text or "").splitlines() if line.strip()]


def _form_data(form: EngagementForm) -> service.EngagementData:
    return service.EngagementData(
        name=form.name.data,
        client_name=form.client_name.data,
        description=form.description.data or "",
        primary_target_url=form.primary_target_url.data,
        start_date=form.start_date.data,
        end_date=form.end_date.data,
        rules_of_engagement=form.rules_of_engagement.data or "",
        authorized_scope=_lines(form.authorized_scope.data),
        excluded_scope=_lines(form.excluded_scope.data),
        authorized_methods=form.authorized_methods.data or [],
        credential_references=service.parse_credential_references(form.credential_references.data),
        tester_ids=form.tester_ids.data or [],
    )


@engagements_bp.route("/")
@permission_required("engagement.view")
def index():
    query = service.visible_engagements_query(current_user)
    status = request.args.get("status", "")
    search = request.args.get("q", "").strip()[:100]
    if status in EngagementStatus.ALL:
        query = query.where(Engagement.status == status)
    if search:
        pattern = "%" + search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        query = query.where(
            or_(
                Engagement.name.ilike(pattern, escape="\\"),
                Engagement.client_name.ilike(pattern, escape="\\"),
            )
        )
    page = db.paginate(
        query.order_by(Engagement.created_at.desc()), per_page=20, error_out=False
    )
    return render_template(
        "engagements/index.html",
        page=page,
        status=status,
        search=search,
        statuses=EngagementStatus.ALL,
    )


@engagements_bp.route("/new", methods=["GET", "POST"])
@permission_required("engagement.create")
def create():
    form = EngagementForm()
    form.tester_ids.choices = _tester_choices()
    if form.validate_on_submit():
        try:
            engagement = service.create_engagement(_form_data(form), current_user)
        except service.EngagementError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            db.session.commit()
            flash("Engagement created as a draft. Record authorization before testing.", "success")
            return redirect(url_for("engagements.detail", engagement_id=engagement.id))
    return render_template("engagements/form.html", form=form, engagement=None)


@engagements_bp.route("/<int:engagement_id>")
@permission_required("engagement.view")
def detail(engagement_id: int):
    engagement = _load_engagement(engagement_id)
    return render_template(
        "engagements/detail.html",
        engagement=engagement,
        authorization_form=AuthorizationForm(),
        scope_form=ScopeCheckForm(),
        status_form=StatusForm(),
        decision=None,
        authorization_current=service.authorization_is_current(engagement),
        transitions=sorted(service.ALLOWED_TRANSITIONS[engagement.status]),
        methods=TESTING_METHODS,
    )


@engagements_bp.route("/<int:engagement_id>/edit", methods=["GET", "POST"])
@permission_required("engagement.edit")
def edit(engagement_id: int):
    engagement = _load_engagement(engagement_id)
    form = EngagementForm(obj=engagement)
    form.tester_ids.choices = _tester_choices()
    if request.method == "GET":
        form.authorized_scope.data = "\n".join(entry.value for entry in engagement.inclusions)
        form.excluded_scope.data = "\n".join(entry.value for entry in engagement.exclusions)
        form.credential_references.data = "\n".join(
            f"{item['label']} | {item['reference']}" for item in engagement.credential_references
        )
        form.tester_ids.data = [user.id for user in engagement.testers]
    if form.validate_on_submit():
        try:
            revoked = service.update_engagement(engagement, _form_data(form), current_user)
        except service.EngagementError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            db.session.commit()
            if revoked:
                flash(
                    "Scope changed, so the client authorization was revoked. "
                    "Record a new authorization before testing.",
                    "warning",
                )
            else:
                flash("Engagement updated.", "success")
            return redirect(url_for("engagements.detail", engagement_id=engagement.id))
    return render_template("engagements/form.html", form=form, engagement=engagement)


@engagements_bp.route("/<int:engagement_id>/authorize", methods=["POST"])
@permission_required("engagement.authorize")
def authorize(engagement_id: int):
    engagement = _load_engagement(engagement_id)
    form = AuthorizationForm()
    if not form.validate_on_submit():
        flash("Complete every authorization field and tick the confirmation.", "danger")
    else:
        try:
            service.confirm_authorization(
                engagement,
                current_user,
                form.authorization_reference.data,
                form.authorization_signatory.data,
            )
        except service.EngagementError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            db.session.commit()
            flash("Client authorization recorded.", "success")
    return redirect(url_for("engagements.detail", engagement_id=engagement_id))


@engagements_bp.route("/<int:engagement_id>/status", methods=["POST"])
@permission_required("engagement.manage_status")
def change_status(engagement_id: int):
    engagement = _load_engagement(engagement_id)
    form = StatusForm()
    if form.validate_on_submit():
        try:
            service.transition(engagement, form.status.data, current_user)
        except service.EngagementError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            db.session.commit()
            flash(f"Engagement is now {engagement.status}.", "success")
    return redirect(url_for("engagements.detail", engagement_id=engagement_id))


@engagements_bp.route("/<int:engagement_id>/scope-check", methods=["POST"])
@permission_required("scope.check")
def scope_check(engagement_id: int):
    engagement = _load_engagement(engagement_id)
    form = ScopeCheckForm()
    decision = None
    if form.validate_on_submit():
        decision = service.check_target(
            engagement, form.target.data, current_user, resolve=form.resolve.data
        )
        db.session.commit()
    return render_template(
        "engagements/detail.html",
        engagement=engagement,
        authorization_form=AuthorizationForm(formdata=None),
        scope_form=form,
        status_form=StatusForm(formdata=None),
        decision=decision,
        authorization_current=service.authorization_is_current(engagement),
        transitions=sorted(service.ALLOWED_TRANSITIONS[engagement.status]),
        methods=TESTING_METHODS,
    )
