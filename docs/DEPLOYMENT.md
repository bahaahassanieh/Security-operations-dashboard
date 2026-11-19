# Deployment

## Requirements

Kali Linux with Python 3.11 or newer. No cloud services or subscriptions are needed.

## Install

```bash
scripts/setup.sh
```

```bash
FLASK_APP=wsgi:app .venv/bin/flask ptp create-admin
```

```bash
scripts/run.sh
```

The platform listens on `127.0.0.1:8088` by default. Settings are in `.env`; see `.env.example`.

`scripts/run.sh` starts both the web server and the background worker. Stopping it stops both.

## Health checks

| Endpoint | Meaning |
|---|---|
| `/healthz` | The process is running |
| `/readyz` | The database is reachable and migrated |

## LAN access

The platform refuses to bind to a network address over plain HTTP. Terminate TLS in a reverse proxy
such as nginx, then set these values in `.env`:

```
PTP_BIND_HOST=127.0.0.1
PTP_COOKIE_SECURE=true
PTP_ALLOWED_HOSTS=pentest.lab.internal
PTP_PROXY_COUNT=1
```

The proxy must forward `Host`, `X-Forwarded-For` and `X-Forwarded-Proto`. Restrict access to authorized
LAN addresses with the host firewall.

## Backup

Backups are safe while the platform is running. Each one is integrity-checked and gets a SHA-256 file.

```bash
scripts/backup.sh
```

Also protect `.env`. A restored database needs the original `PTP_AUDIT_KEY` to verify its audit log.
Raw tool output in `instance/jobs/` is not part of the database backup, so copy it separately if you need it.

## Restore

Stop the platform first. The current database is backed up automatically before it is replaced.

```bash
scripts/restore.sh backups/platform-YYYYMMDDTHHMMSSffffffZ.db
```

## Upgrade

Stop the platform, update the code, then re-run setup. It backs up the database, applies migrations
and keeps your configuration and data.

```bash
scripts/setup.sh
```
