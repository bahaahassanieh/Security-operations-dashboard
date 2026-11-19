# Sentinel PT

A self-hosted web application penetration testing and assessment platform for Kali Linux.

**Status: Phase 6 complete — all seven planned phases delivered (Phases 4 and 5 at reduced scope).**
Authentication, RBAC, engagements, scope enforcement, audit logging, the dashboard, reconnaissance, application
mapping, the OWASP WSTG and API Top 10 libraries, scanner result import, correlation, manual validation, the
manual testing workspace, the evidence repository, CVSS scoring, remediation and retest tracking, and HTML/PDF
report generation all work today. The platform imports vulnerability scanner results but does not launch
vulnerability scans or send attack payloads.

> Use this platform only against systems you have explicit written authorization to test.

## Quick start

```bash
scripts/setup.sh
```

```bash
FLASK_APP=wsgi:app .venv/bin/flask ptp create-admin
```

```bash
scripts/run.sh
```

Open <http://127.0.0.1:8088> and sign in with the one-time password printed by `create-admin`.

## Documentation

| Document | Contents |
|---|---|
| [User manual](docs/USER_MANUAL.md) | Running an engagement from creation to authorization |
| [Architecture](docs/ARCHITECTURE.md) | Structure, data model and key design decisions |
| [Tools](docs/TOOLS.md) | Integrated tools, how each is run and what has been validated |
| [Security](docs/SECURITY.md) | Controls, threat model, Phase 1 review and known limitations |
| [Deployment](docs/DEPLOYMENT.md) | Install, LAN access, backup, restore and upgrades |
| [Developer guide](docs/DEVELOPER.md) | Conventions, tests and migrations |
| [Changelog](CHANGELOG.md) | Release history |

## Tests

```bash
.venv/bin/pip install -r requirements-dev.txt
```

```bash
.venv/bin/python -m pytest --cov=app
```
