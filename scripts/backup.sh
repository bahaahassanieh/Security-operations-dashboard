#!/usr/bin/env bash
# Create a verified database backup. Safe while the platform is running.
# Usage: scripts/backup.sh [destination-directory]
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export FLASK_APP=wsgi:app
if [ "$#" -ge 1 ]; then
  exec .venv/bin/flask ptp backup --dest "$1"
fi
exec .venv/bin/flask ptp backup
