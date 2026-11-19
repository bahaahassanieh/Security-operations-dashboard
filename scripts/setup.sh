#!/usr/bin/env bash
# Install or upgrade the platform. Safe to re-run: existing configuration and data are kept.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

command -v python3 >/dev/null || { echo "python3 is required." >&2; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
  || { echo "Python 3.11 or newer is required." >&2; exit 1; }

echo "[1/5] Python environment"
[ -d .venv ] || python3 -m venv .venv
.venv/bin/pip install --quiet --upgrade pip
if [ -f requirements.lock ]; then
  .venv/bin/pip install --quiet -r requirements.lock
else
  .venv/bin/pip install --quiet -r requirements.txt
fi

echo "[2/5] Configuration"
if [ ! -f .env ]; then
  cp .env.example .env
  secret="$(.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(48))')"
  audit="$(.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(48))')"
  sed -i "s|^PTP_SECRET_KEY=.*|PTP_SECRET_KEY=${secret}|; s|^PTP_AUDIT_KEY=.*|PTP_AUDIT_KEY=${audit}|" .env
  echo "      Generated .env with new keys."
else
  echo "      Keeping existing .env."
fi
chmod 600 .env
mkdir -p instance backups
chmod 700 instance backups

export FLASK_APP=wsgi:app

if [ -f instance/platform.db ]; then
  echo "[3/5] Backing up the existing database before upgrading"
  .venv/bin/flask ptp backup
else
  echo "[3/5] No existing database to back up"
fi

echo "[4/5] Database migrations"
.venv/bin/flask db upgrade

echo "[5/5] Roles, permissions and tool detection"
.venv/bin/flask ptp seed
.venv/bin/flask ptp tools

cat <<'EOF'

Setup complete.
  Create the first administrator:  FLASK_APP=wsgi:app .venv/bin/flask ptp create-admin
  Start the platform:              scripts/run.sh
EOF
