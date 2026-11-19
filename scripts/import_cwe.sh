#!/usr/bin/env bash
# Import the official CWE catalog XML to enrich the CWE reference.
# Download from https://cwe.mitre.org/data/downloads.html (e.g. cwec_latest.xml.zip), unzip, then:
#   scripts/import_cwe.sh cwec_v4.xx.xml
set -euo pipefail
[ "$#" -eq 1 ] || { echo "Usage: $0 <cwec_catalog.xml>" >&2; exit 2; }
SOURCE="$(realpath "$1")"
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export FLASK_APP=wsgi:app
exec .venv/bin/flask ptp import-cwe "$SOURCE"
