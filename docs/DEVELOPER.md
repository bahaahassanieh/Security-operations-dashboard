# Developer guide

## Setup

```bash
scripts/setup.sh
```

```bash
.venv/bin/pip install -r requirements-dev.txt
```

## Rules

- Keep HTTP handling in `blueprints/` and business rules in `services/`.
- Use SQLAlchemy for all database access.
- Protect every route with `permission_required`, and load engagements through
  `get_visible_engagement` so object-level access is enforced.
- Call `authorize_execution` before any action that touches a target.
- Run tools with argument arrays, never a shell, and with timeouts.
- Call `audit.record` for security-relevant actions, inside the same transaction as the change.
- Put no inline script, style or event handlers in templates. The CSP blocks them.
- Never set a finding to `confirmed` automatically.

## Adding a tool

Add a `ToolDefinition` to `app/tools/registry.py`, write a parser in `app/recon/parsers.py` that treats
all output as hostile, and call the tool through `ReconContext.execute` after `ReconContext.gate`.

## Test case library

Built-in cases live in `app/methodology/wstg.py` and `app/methodology/api_top10.py` and are seeded by
`flask ptp seed`. Custom cases are imported with `flask ptp import-testcases <file>` through
`library.import_test_cases`, which validates every field and refuses to overwrite a built-in case or to reuse a
built-in framework name. A finding can be created pre-linked to a case; `create_manual_finding` accepts an
optional `test_case_id`.

## Assessment orchestrator

`jobs.create_assessment_job` queues a `full_assessment` that runs the modules in `ASSESSMENT_ORDER`
(recon, then mapping, then the passive-findings module) — only those whose method is authorized and
tools are installed. Each `ReconModule` carries a `covers` tuple of WSTG/API test ids; when a module
completes, `library.record_automated_coverage` marks those cases in-progress without overriding a
tester's result. Keep every automated module non-intrusive: no attack payloads, no exploit tools.

## CWE reference

The bundled CWE data is in `app/reference/cwe_data.py`; the service (seeding, catalog parsing, import,
lookup) is in `app/reference/cwe.py`. `flask ptp seed` seeds the bundled reference and matching CWE
test cases; `flask ptp import-cwe <file>` enriches the reference from MITRE's catalog XML. The parser
uses defusedxml and matches elements by local name. Findings display `cwe.cwe_for(finding.cwe_id)`.

## Reporting

CVSS scoring is in `app/reporting/cvss.py` (v3.1, exact algorithm — keep the known-answer tests passing). Report
data gathering is in `app/reporting/data.py`; HTML and PDF rendering in `app/reporting/render.py`. Report and
evidence files are stored outside the web root with 0600 permissions and served only as attachments. Never count
an unverified detection as confirmed in a report.

## Tests

```bash
.venv/bin/python -m pytest --cov=app
```

| Suite | Purpose |
|---|---|
| `tests/integration` | Workflows, schema, migrations, backup |
| `tests/security` | Scope bypasses, access control, sessions, CSRF, XSS |

## Migrations

Migrations must be additive and must preserve existing data.

```bash
FLASK_APP=wsgi:app .venv/bin/flask db migrate -m "describe the change"
```

Review the generated revision, then apply it:

```bash
FLASK_APP=wsgi:app .venv/bin/flask db upgrade
```

`tests/integration/test_platform.py` fails if the models and migrations drift apart.

## Adding a permission

Add it to `PERMISSIONS` in `services/authz.py`, then run `flask ptp seed`. Administrators receive it
automatically. Existing custom roles are left unchanged.
