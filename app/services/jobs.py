"""Assessment job queue, lifecycle controls and the background worker.

Jobs live in the database, so no external broker is required and a job survives a restart.
"""
from __future__ import annotations

import fcntl
import logging
import signal
import time
from pathlib import Path

from flask import Flask, current_app
from sqlalchemy import update

from app.extensions import db
from app.models import (
    AuditOutcome,
    Engagement,
    ExecutionJob,
    JobEvent,
    JobStatus,
    User,
    utcnow,
)
from app.manual.service import run_passive_findings
from app.mapping.modules import MAPPING_MODULES
from app.methodology import library as methodology_library
from app.recon.modules import MODULES, JobCancelled, ReconContext, ReconModule
from app.services import audit
from app.services.engagements import execution_precondition_failure
from app.tools.registry import resolve_tool

logger = logging.getLogger("ptp.jobs")

JOB_TYPE_RECON = "reconnaissance"
JOB_TYPE_MAPPING = "application_mapping"
JOB_TYPE_ASSESSMENT = "full_assessment"

# A no-traffic module that turns already-collected data into unverified candidate findings.
PASSIVE_MODULES = {
    "passive_findings": ReconModule(
        "passive_findings", "Passive findings",
        "Turn collected reconnaissance and mapping data into unverified candidate findings. Sends no traffic.",
        "passive_recon", (), run_passive_findings,
        covers=("WSTG-SESS-02", "WSTG-CLNT-09", "WSTG-CONF-07", "WSTG-CONF-02", "WSTG-ATHN-01", "WSTG-CONF-04"),
    )
}
ALL_MODULES = {**MODULES, **MAPPING_MODULES, **PASSIVE_MODULES}
# The order a full assessment runs modules in: reconnaissance, then mapping, then passive analysis.
ASSESSMENT_ORDER = list(MODULES) + list(MAPPING_MODULES) + list(PASSIVE_MODULES)
_POLL_SECONDS = 2.0
_HEARTBEAT_MAX_AGE_SECONDS = 20


class JobError(ValueError):
    """A user-correctable problem with a job request."""


class WorkerAlreadyRunning(RuntimeError):
    """Another worker holds the lock."""


class _WorkerState:
    stopping = False


def _event(job: ExecutionJob, message: str, level: str = "info") -> None:
    db.session.add(JobEvent(job_id=job.id, level=level, message=message[:1000]))


def available_modules(engagement: Engagement, catalog: dict | None = None) -> list[dict]:
    """Describe each module and whether it can run on this engagement right now."""
    authorized = set(engagement.authorized_methods or [])
    result = []
    for module in (MODULES if catalog is None else catalog).values():
        missing = [tool for tool in module.tools if resolve_tool(tool) is None]
        reason = None
        if module.method not in authorized:
            reason = f"Method '{module.method}' is not authorized for this engagement."
        elif module.tools and len(missing) == len(module.tools):
            reason = f"Not installed: {', '.join(missing)}."
        result.append({"module": module, "missing": missing, "blocked_reason": reason})
    return result


def create_recon_job(engagement: Engagement, actor: User, selected: list[str]) -> ExecutionJob:
    """Validate and queue a reconnaissance job. The caller commits."""
    return _create_job(engagement, actor, selected, JOB_TYPE_RECON, MODULES, {}, auto_passive=True)


def create_mapping_job(
    engagement: Engagement, actor: User, selected: list[str], options: dict
) -> ExecutionJob:
    """Validate and queue an application mapping job. The caller commits."""
    return _create_job(engagement, actor, selected, JOB_TYPE_MAPPING, MAPPING_MODULES, options, auto_passive=True)


def assessment_plan(engagement: Engagement) -> list[dict]:
    """The assessment modules in run order, each with whether it can run on this engagement."""
    states = {item["module"].name: item for item in available_modules(engagement, ALL_MODULES)}
    return [states[name] for name in ASSESSMENT_ORDER if name in states]


def create_assessment_job(engagement: Engagement, actor: User, options: dict | None = None) -> ExecutionJob:
    """Queue a full non-intrusive assessment: reconnaissance, mapping and passive analysis, in order.

    Only modules whose method is authorized and whose tools are installed are included. The caller commits.
    """
    modules = [item["module"].name for item in assessment_plan(engagement) if item["blocked_reason"] is None]
    if not modules:
        raise JobError(
            "No assessment modules can run. Check the engagement's authorized testing methods and installed tools."
        )
    return _create_job(engagement, actor, modules, JOB_TYPE_ASSESSMENT, ALL_MODULES, options or {})


def _create_job(
    engagement: Engagement, actor: User, selected: list[str], job_type: str, catalog: dict, options: dict,
    auto_passive: bool = False,
) -> ExecutionJob:
    modules = [name for name in catalog if name in set(selected)]
    if not modules or len(modules) != len(set(selected)):
        raise JobError("Select at least one valid module.")
    states = {item["module"].name: item for item in available_modules(engagement, catalog)}
    for name in modules:
        failure = execution_precondition_failure(engagement, actor, catalog[name].method)
        if failure is None:
            failure = states[name]["blocked_reason"]
        if failure:
            raise JobError(f"{catalog[name].label}: {failure}")
    # Every automated job ends by turning its collected data into unverified candidate findings,
    # when the engagement authorizes passive reconnaissance.
    if auto_passive and "passive_findings" not in modules:
        passive = PASSIVE_MODULES["passive_findings"]
        if execution_precondition_failure(engagement, actor, passive.method) is None:
            modules = [*modules, "passive_findings"]
    active = db.session.scalar(
        db.select(ExecutionJob).where(
            ExecutionJob.engagement_id == engagement.id,
            ExecutionJob.status.in_(JobStatus.ACTIVE),
        )
    )
    if active is not None:
        raise JobError(f"Job #{active.id} is already running for this engagement.")
    job = ExecutionJob(
        engagement_id=engagement.id,
        requested_by_id=actor.id,
        job_type=job_type,
        plan={"modules": modules, "current": 0, "options": options},
    )
    db.session.add(job)
    db.session.flush()
    _event(job, f"Queued modules: {', '.join(modules)}.")
    audit.record(
        "job.created",
        engagement_id=engagement.id,
        object_type="job",
        object_id=job.id,
        details={"type": job_type, "modules": modules, "options": options},
        actor=actor,
    )
    return job


def control_job(job: ExecutionJob, action: str, actor: User) -> None:
    """Apply cancel, pause or resume. The caller commits."""
    if job.status not in JobStatus.ACTIVE:
        raise JobError("This job has already finished.")
    if action == "cancel":
        job.cancel_requested = True
        if job.status == JobStatus.QUEUED:
            job.status = JobStatus.CANCELLED
            job.finished_at = utcnow()
        _event(job, f"Cancellation requested by {actor.username}.", "warning")
    elif action == "pause":
        if job.status != JobStatus.RUNNING:
            raise JobError("Only a running job can be paused.")
        job.pause_requested = True
        _event(job, f"Pause requested by {actor.username}. It applies after the current module.")
    elif action == "resume":
        if not job.pause_requested and job.status != JobStatus.PAUSED:
            raise JobError("This job is not paused.")
        job.pause_requested = False
        _event(job, f"Resumed by {actor.username}.")
    else:
        raise JobError("Unknown action.")
    audit.record(
        f"job.{action}",
        engagement_id=job.engagement_id,
        object_type="job",
        object_id=job.id,
        actor=actor,
    )


def _heartbeat_path() -> Path:
    return Path(current_app.config["JOB_DIR"]) / "worker.heartbeat"


def _touch_heartbeat() -> None:
    path = _heartbeat_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.touch()


def worker_online() -> bool:
    """True when a worker has reported in recently."""
    try:
        return time.time() - _heartbeat_path().stat().st_mtime < _HEARTBEAT_MAX_AGE_SECONDS
    except OSError:
        return False


def claim_next_job() -> ExecutionJob | None:
    """Atomically claim the oldest queued job."""
    candidate = db.session.scalar(
        db.select(ExecutionJob.id)
        .filter_by(status=JobStatus.QUEUED)
        .order_by(ExecutionJob.id)
        .limit(1)
    )
    if candidate is None:
        db.session.rollback()
        return None
    claimed = db.session.execute(
        update(ExecutionJob)
        .where(ExecutionJob.id == candidate, ExecutionJob.status == JobStatus.QUEUED)
        .values(status=JobStatus.RUNNING, started_at=utcnow())
    ).rowcount
    db.session.commit()
    return db.session.get(ExecutionJob, candidate) if claimed else None


def _record_coverage(job: ExecutionJob, module) -> None:
    """Record automated methodology coverage for a completed module. Never fails the module."""
    if not getattr(module, "covers", ()):
        return
    try:
        methodology_library.record_automated_coverage(job.engagement, module.covers, job.requested_by)
        db.session.commit()
    except Exception:
        db.session.rollback()
        logger.exception("coverage_record_failed", extra={"job": job.id, "module_name": module.name})


def _flag(job_id: int, column) -> bool:
    value = db.session.scalar(db.select(column).where(ExecutionJob.id == job_id))
    db.session.rollback()
    return bool(value)


def _finish(job: ExecutionJob, status: str, message: str, level: str = "info") -> None:
    job.status = status
    job.finished_at = utcnow()
    if status == JobStatus.COMPLETED:
        job.progress = 100
    if status == JobStatus.FAILED:
        job.error_message = message[:1000]
    _event(job, message, level)
    audit.record(
        "job.finished",
        outcome=AuditOutcome.SUCCESS if status == JobStatus.COMPLETED else AuditOutcome.FAILURE,
        engagement_id=job.engagement_id,
        object_type="job",
        object_id=job.id,
        details={"status": status},
        actor=job.requested_by,
    )
    db.session.commit()


def _wait_while_paused(job: ExecutionJob) -> None:
    """Hold at a module boundary until the job is resumed or cancelled."""
    if not _flag(job.id, ExecutionJob.pause_requested):
        return
    job.status = JobStatus.PAUSED
    _event(job, "Job paused.")
    db.session.commit()
    while _flag(job.id, ExecutionJob.pause_requested):
        if _flag(job.id, ExecutionJob.cancel_requested) or _WorkerState.stopping:
            break
        _touch_heartbeat()
        time.sleep(1)
    db.session.refresh(job)
    job.status = JobStatus.RUNNING
    db.session.commit()


def execute_job(job: ExecutionJob) -> None:
    """Run a claimed job's remaining modules in order."""
    job_id = job.id

    def should_stop() -> bool:
        _touch_heartbeat()
        return _WorkerState.stopping or _flag(job_id, ExecutionJob.cancel_requested)

    modules = list(job.plan["modules"])
    failures = 0
    try:
        for index in range(job.plan.get("current", 0), len(modules)):
            _wait_while_paused(job)
            if should_stop():
                raise JobCancelled
            module = ALL_MODULES[modules[index]]
            failure = execution_precondition_failure(job.engagement, job.requested_by, module.method)
            if failure:
                _finish(job, JobStatus.FAILED, f"Stopped: {failure}", "error")
                return
            job.plan = {**job.plan, "current": index}
            job.progress = int(100 * index / len(modules))
            _event(job, f"Starting {module.label}.")
            db.session.commit()
            context = ReconContext(
                job, job.engagement, job.requested_by, module, should_stop,
                lambda: _wait_while_paused(job),
            )
            try:
                module.run(context)
                _record_coverage(job, module)
            except JobCancelled:
                raise
            except Exception:  # A failing module must not stop the remaining ones.
                db.session.rollback()
                failures += 1
                logger.exception("module_failed", extra={"job": job_id, "module_name": module.name})
                _event(job, f"{module.label} failed unexpectedly.", "error")
                db.session.commit()
    except JobCancelled:
        db.session.rollback()
        if _WorkerState.stopping and not _flag(job_id, ExecutionJob.cancel_requested):
            job.status = JobStatus.QUEUED  # Resume from this module after the restart.
            _event(job, "Worker stopped. The job will resume when it restarts.", "warning")
            db.session.commit()
        else:
            _finish(job, JobStatus.CANCELLED, "Job cancelled.", "warning")
        return
    summary = "Job completed." if not failures else f"Job completed with {failures} failed module(s)."
    _finish(job, JobStatus.COMPLETED, summary, "warning" if failures else "info")


def run_worker(app: Flask) -> None:
    """Process queued jobs until the worker receives SIGTERM or SIGINT."""
    job_dir = Path(app.config["JOB_DIR"])
    job_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = (job_dir / "worker.lock").open("w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        raise WorkerAlreadyRunning("Another worker is already running.") from exc

    def request_stop(_signum, _frame) -> None:
        _WorkerState.stopping = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    _WorkerState.stopping = False

    with app.app_context():
        interrupted = db.session.scalars(
            db.select(ExecutionJob).where(
                ExecutionJob.status.in_((JobStatus.RUNNING, JobStatus.PAUSED))
            )
        ).all()
        for job in interrupted:
            job.status = JobStatus.QUEUED
            _event(job, "Recovered after a worker restart.", "warning")
        db.session.commit()
        logger.info("worker_started", extra={"event": "worker_started"})
        while not _WorkerState.stopping:
            _touch_heartbeat()
            job = claim_next_job()
            if job is not None:
                execute_job(job)
            else:
                time.sleep(_POLL_SECONDS)
            db.session.remove()
    logger.info("worker_stopped", extra={"event": "worker_stopped"})
