#!/usr/bin/env bash
# Restore a backup. Stop the platform first. The current database is backed up automatically.
# Usage: scripts/restore.sh backups/platform-YYYYMMDDTHHMMSSZ.db
set -euo pipefail
[ "$#" -eq 1 ] || { echo "Usage: $0 <backup-file>" >&2; exit 2; }
BACKUP="$(realpath "$1")"
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export FLASK_APP=wsgi:app
.venv/bin/flask ptp restore "$BACKUP"
.venv/bin/flask db upgrade
.venv/bin/flask ptp verify-audit
