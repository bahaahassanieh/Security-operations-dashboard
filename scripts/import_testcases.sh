#!/usr/bin/env bash
# Import custom test cases into the library from a JSON (or YAML) file.
# Usage: scripts/import_testcases.sh path/to/testcases.json
set -euo pipefail
[ "$#" -eq 1 ] || { echo "Usage: $0 <testcases.json>" >&2; exit 2; }
SOURCE="$(realpath "$1")"
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export FLASK_APP=wsgi:app
exec .venv/bin/flask ptp import-testcases "$SOURCE"
