"""Consistent SQLite backup and verified restore."""
from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from flask import current_app
from sqlalchemy.engine import make_url


class BackupError(RuntimeError):
    """A backup or restore could not be completed safely."""


def database_path() -> Path:
    """Return the SQLite file path, refusing non-file databases."""
    url = make_url(current_app.config["SQLALCHEMY_DATABASE_URI"])
    if url.get_backend_name() != "sqlite" or not url.database or url.database == ":memory:":
        raise BackupError("Backup and restore support file-based SQLite databases only.")
    return Path(url.database)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _copy_database(source: Path, destination: Path) -> None:
    """Copy using SQLite's online backup API, which is safe while the app is running."""
    descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    with closing(sqlite3.connect(f"file:{source}?mode=ro", uri=True)) as src:
        with closing(sqlite3.connect(destination)) as dst:
            src.backup(dst)


def _check_integrity(path: Path) -> None:
    try:
        with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as connection:
            result = connection.execute("PRAGMA integrity_check").fetchone()[0]
            connection.execute("SELECT count(*) FROM alembic_version").fetchone()
    except sqlite3.DatabaseError as exc:
        raise BackupError(f"{path.name} is not a valid platform database: {exc}") from exc
    if result != "ok":
        raise BackupError(f"Integrity check failed for {path.name}: {result}")


def create_backup(destination_dir: Path | None = None) -> Path:
    """Create a verified backup with a SHA-256 sidecar and owner-only permissions."""
    source = database_path()
    if not source.exists():
        raise BackupError(f"Database not found: {source}")
    directory = Path(destination_dir or current_app.config["BACKUP_DIR"])
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination = directory / f"platform-{stamp}.db"
    _copy_database(source, destination)
    _check_integrity(destination)
    sidecar = destination.with_suffix(".db.sha256")
    sidecar.write_text(f"{_sha256(destination)}  {destination.name}\n")
    sidecar.chmod(0o600)
    return destination


def restore_backup(backup_file: Path) -> Path:
    """Verify a backup, save the current database, then atomically replace it.

    Stop the application before restoring. Returns the path of the safety backup.
    """
    backup_file = Path(backup_file).resolve()
    sidecar = backup_file.with_suffix(".db.sha256")
    if not backup_file.is_file() or not sidecar.is_file():
        raise BackupError("The backup file and its .sha256 sidecar are both required.")
    expected = sidecar.read_text().split()[0]
    if _sha256(backup_file) != expected:
        raise BackupError("Checksum mismatch: the backup is corrupt or has been modified.")
    _check_integrity(backup_file)

    target = database_path()
    safety_copy = create_backup() if target.exists() else Path()
    staging = target.with_suffix(".restore")
    shutil.copyfile(backup_file, staging)
    staging.chmod(0o600)
    for suffix in ("-wal", "-shm"):
        Path(f"{target}{suffix}").unlink(missing_ok=True)
    os.replace(staging, target)
    return safety_copy
