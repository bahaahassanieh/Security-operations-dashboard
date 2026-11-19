"""Operational commands: ``flask ptp <command>``."""
from __future__ import annotations

import sys
from pathlib import Path

import click
from flask import current_app
from flask.cli import AppGroup

from app.extensions import db
from app.models import Role
from app.services import accounts, audit, authz, backup, jobs
from app.methodology import library
from app.reference import cwe
from app.tools import registry

ptp_cli = AppGroup("ptp", help="Platform administration commands.")


@ptp_cli.command("seed")
def seed_command() -> None:
    """Create default roles and permissions (safe to re-run)."""
    authz.seed_rbac()
    count = library.seed_test_cases()
    cwe_entries, _ = cwe.seed_cwe()
    click.echo(f"Roles, permissions, {count} test cases and {cwe_entries} CWE references are up to date.")


@ptp_cli.command("create-admin")
@click.option("--username", prompt=True)
@click.option("--email", prompt=True)
@click.option("--full-name", default="")
def create_admin(username: str, email: str, full_name: str) -> None:
    """Create an administrator with a one-time password that must be changed at first login."""
    authz.seed_rbac()
    role = db.session.scalar(db.select(Role).filter_by(name="Administrator"))
    try:
        _, password = accounts.create_user(username, email, full_name, role)
    except accounts.AccountError as exc:
        db.session.rollback()
        raise click.ClickException(str(exc)) from exc
    db.session.commit()
    click.echo(f"Administrator '{username}' created.")
    click.echo(f"One-time password (shown once): {password}")


@ptp_cli.command("import-cwe")
@click.argument("source", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def import_cwe(source: Path) -> None:
    """Import the official CWE catalog XML (cwec_*.xml) to enrich the CWE reference."""
    cwe.ensure_cwe()
    try:
        records = cwe.load_cwe_file(source)
        summary = cwe.import_cwe_catalog(records)
    except cwe.CweError as exc:
        db.session.rollback()
        raise click.ClickException(str(exc)) from exc
    click.echo(f"{summary.created} CWE references created, {summary.updated} updated, {summary.skipped} skipped.")
    if summary.changed == 0:
        sys.exit(1)


@ptp_cli.command("import-testcases")
@click.argument("source", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def import_testcases(source: Path) -> None:
    """Import custom test cases from a JSON or YAML file into the test case library."""
    library.ensure_library()
    try:
        records = library.load_testcase_file(source)
        summary = library.import_test_cases(records)
    except library.MethodologyError as exc:
        db.session.rollback()
        raise click.ClickException(str(exc)) from exc
    click.echo(f"{summary.created} created, {summary.updated} updated, {summary.skipped} skipped.")
    for error in summary.errors[:50]:
        click.echo(f"  - {error}")
    if summary.changed == 0:
        sys.exit(1)


@ptp_cli.command("tools")
def tools_command() -> None:
    """Detect installed security tools and update the registry."""
    for row in registry.sync_registry():
        click.echo(f"{row.name:<18} {row.health_status:<9} {row.version or '-':<14} {row.executable_path or ''}")


@ptp_cli.command("worker")
def worker_command() -> None:
    """Run the background worker that executes assessment jobs."""
    try:
        jobs.run_worker(current_app._get_current_object())
    except jobs.WorkerAlreadyRunning as exc:
        raise click.ClickException(str(exc)) from exc


@ptp_cli.command("verify-audit")
def verify_audit() -> None:
    """Verify the audit log hash chain. Exits non-zero if it is broken."""
    status = audit.verify_chain()
    click.echo(f"{status.message} ({status.entries_checked} entries verified)")
    if not status.valid:
        sys.exit(1)


@ptp_cli.command("backup")
@click.option("--dest", type=click.Path(file_okay=False, path_type=Path))
def backup_command(dest: Path | None) -> None:
    """Create a verified database backup."""
    try:
        click.echo(f"Backup created: {backup.create_backup(dest)}")
    except backup.BackupError as exc:
        raise click.ClickException(str(exc)) from exc


@ptp_cli.command("restore")
@click.argument("backup_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--yes", is_flag=True, help="Confirm replacing the current database.")
def restore_command(backup_file: Path, yes: bool) -> None:
    """Restore a backup. Stop the application first. The current database is saved beforehand."""
    if not yes:
        click.confirm("Replace the current database with this backup?", abort=True)
    try:
        safety = backup.restore_backup(backup_file)
    except backup.BackupError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Restored {backup_file.name}. Previous database saved to: {safety}")
