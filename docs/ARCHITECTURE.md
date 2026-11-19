# Architecture

## Layout

```
app/
  __init__.py        Application factory
  config.py          Environment-driven configuration
  web.py             Request hooks, security headers, error handling
  navigation.py      Sidebar definition
  cli.py             `flask ptp` administration commands
  models/            SQLAlchemy models, grouped by domain
  services/          Business logic, independent of HTTP
    scope.py         Scope engine (no Flask or database dependencies)
    engagements.py   Lifecycle, authorization and the execution gate
    audit.py         Hash-chained audit log
    authz.py         Permission catalogue, role seeding, route decorator
    accounts.py      Passwords, lockout, user administration
    dashboard.py     Metrics, limited to what the user may see
    backup.py        Verified backup and restore
    settings.py      Allow-listed runtime settings
    jobs.py          Job queue, controls and the background worker
  tools/             Tool registry and least-privilege process runner
  recon/             Reconnaissance modules, output parsers and asset inventory
  mapping/           Read-only HTTP client, page extraction, categorization and crawler
  findings/          Report parsers, vulnerability taxonomy, correlation and validation
  methodology/       OWASP WSTG v4.2 and API Top 10 libraries, and engagement progress
  manual/            Business logic playbooks, authorization matrix, offline analyzers and passive review
  reporting/         CVSS calculator, evidence repository, remediation, report data and HTML/PDF rendering
  blueprints/        auth, dashboard, engagements, admin, audit, api, health, tools, recon, assets, mapping, findings, methodology, manual, apitest, evidence, reports, retesting
  templates/ static/ User interface (all frontend libraries are vendored)
migrations/          Alembic revisions
scripts/             setup, run, backup, restore
tests/               integration/ and security/ suites
```

Routes handle HTTP only. Rules live in `services/`, so background workers in later phases reuse
the same checks as the web interface.

## Data model

| Domain | Tables |
|---|---|
| Identity | `users`, `roles`, `permissions`, `role_permissions` |
| Engagements | `engagements`, `engagement_scope`, `engagement_testers`, `targets` |
| Attack surface | `assets`, `subdomains`, `endpoints`, `technologies` |
| Application map | `endpoint_links`, `endpoint_parameters`, `web_forms`, `web_cookies` |
| Testing | `test_cases`, `test_executions`, `execution_jobs`, `job_events`, `tool_runs`, `tool_registry` |
| Manual testing | `manual_workflows`, `workflow_steps`, `authz_subjects`, `authz_checks`, `authz_results` |
| Findings | `vulnerabilities`, `finding_imports`, `finding_sources`, `finding_status_changes`, `evidence`, `reports`, `remediation`, `retests` |
| Operations | `activity_logs`, `application_settings` |

Tables for later phases already exist so those phases extend the schema through additive migrations.

## The execution gate

`services.engagements.authorize_execution()` is the one path to touching a target. Every tool
integration in later phases must call it first. It denies unless all of these hold:

1. The user holds `assessment.execute` and can access the engagement.
2. The engagement is `active`.
3. A client authorization exists and its fingerprint matches the current scope.
4. Today falls inside the testing window (UTC).
5. The testing method is authorized for this engagement.
6. The target passes scope evaluation, including DNS resolution.

Every decision, allowed or denied, is written to the audit log.

## Scope evaluation order

1. Parse and canonicalize the target. Anything malformed is denied.
2. Deny prohibited addresses (cloud metadata, link-local, multicast, reserved).
3. Deny on any exclusion match.
4. Deny unless an inclusion matches.
5. At execution time, resolve the hostname and deny if any address is prohibited, excluded, or
   non-public without explicit authorization.

## Reconnaissance jobs

The web process only queues jobs in `execution_jobs`. A single worker (`flask ptp worker`, started by
`scripts/run.sh`) claims them and runs modules in order: DNS, subdomains, ports, HTTP services,
fingerprinting, TLS, content discovery, crawl. Each module's results feed the next, and only in-scope
results are carried forward. Engagement status and authorization are rechecked before every module, so
pausing an engagement or changing its scope stops the job. Interrupted jobs resume at their current module.

Raw tool output is stored in `instance/jobs/`. Normalized results are stored in the database.

## Application mapping

The crawler is built in rather than wrapping an external tool, because it must enforce rules on every
request. A host passes the audited execution gate once, and its validated address is pinned for the whole
crawl. Each URL is then checked against scope, the unsafe-link filter and robots.txt before it is requested.
The HTTP client itself refuses every method except GET, HEAD and OPTIONS.

Requests are logged to `instance/jobs/`, without response bodies.

## Findings pipeline

Uploaded reports are parsed into one normalized form, checked against scope, classified and correlated.
Detections of the same weakness type, endpoint and parameter become one finding with several sources. The
same source and evidence fingerprint counts as a duplicate. Imports run in one transaction, so a failed file
leaves nothing behind. A finding can only become Confirmed through a tester's decision backed by tester evidence.

## Manual testing

The manual workspace has no network client. An automated test fails if its modules import networking or process
execution libraries. Testers carry out each test themselves, and the platform records plans, outcomes and evidence.

## Reporting

Reports are built from the database by ``reporting/data.py``, then rendered to self-contained HTML (Jinja,
autoescaped) or PDF (ReportLab). Report and evidence files live outside the web root with 0600 permissions and
are served only through access-controlled routes, as attachments. Only tester-validated findings are counted as
confirmed; unverified detections appear in a clearly labelled appendix when the author opts in.

## PostgreSQL portability

Models use portable types, named constraints and naive UTC timestamps. Audit chain locking already
supports PostgreSQL. A migration would still need PostgreSQL versions of the audit immutability
triggers and a data transfer step.
