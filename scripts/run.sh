#!/usr/bin/env bash
# Start the background worker and the web server. Stopping this script stops both.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

FLASK_APP=wsgi:app .venv/bin/flask ptp worker &
WORKER_PID=$!
.venv/bin/gunicorn -c gunicorn.conf.py wsgi:app &
SERVER_PID=$!

stop() {
  trap - INT TERM EXIT
  kill "$SERVER_PID" "$WORKER_PID" 2>/dev/null
  wait "$SERVER_PID" "$WORKER_PID" 2>/dev/null
}
trap stop INT TERM EXIT

# If either process exits, stop the other rather than running half a platform.
wait -n "$WORKER_PID" "$SERVER_PID"
