# Security

## Controls in place

| Area | Control |
|---|---|
| Passwords | Argon2id, 12+ characters, three character classes, forced change of one-time passwords |
| Brute force | Per-account lockout, per-IP login rate limit, uniform error messages, dummy hash for unknown users |
| Sessions | HttpOnly, SameSite=Strict, 30-minute idle expiry, server-side revocation on logout, password or role change |
| Access control | Permission checks on every route, object-level engagement checks, audited denials, 404 for unassigned engagements |
| CSRF | Tokens on every state-changing request, including the API |
| XSS | Autoescaping and a strict Content Security Policy with no inline script or style |
| Injection | SQLAlchemy parameterized queries, escaped search patterns |
| Host header | Allow-list enforced before routing |
| Secrets | Keys only in `.env` (mode 600), refusal to start without them, credential references instead of credentials |
| Files | Instance directory 700, database and backups 600 |
| Audit | Append-only triggers, HMAC hash chain, redaction of sensitive fields |
| Transport | Refuses to bind to a network address unless secure cookies are enabled |
| Server | Gunicorn only; the Werkzeug debugger is never enabled |

## Scope bypasses covered by tests

Userinfo tricks, suffix confusion, parser differentials, percent-encoded hosts, decimal, hex, octal
and short IPv4 forms, IPv4-mapped, NAT64 and 6to4 IPv6, full-width digits, trailing dots, path
traversal and encoded traversal, path parameters, case changes, scheme and port changes on excluded
paths, cloud metadata addresses, DNS rebinding, failed DNS lookups, and over-broad scope rules.

## Phase 1 review results

| Check | Result |
|---|---|
| Automated tests | All pass (see `tests/`) |
| Bandit static analysis | No medium or high findings |
| pip-audit dependency scan | No known vulnerabilities at review time |
| Clean install and black-box run under Gunicorn | 31 of 31 checks pass |
| 120 concurrent audited writes | Audit chain remained intact |
| Direct database tampering | Detected by `flask ptp verify-audit` |

## Phase 2 review results

| Check | Result |
|---|---|
| Live lab run with real tools | 28 of 28 checks pass |
| Excluded path, recorded by the lab server | Never requested |
| Redirect to an unauthorized host | Never followed |
| Request rate | Stayed within the configured limit |
| Cancelling a running job | Tool process stopped |
| Upgrade rehearsal on a copy of an existing database | Data kept, audit chain intact |

## Phase 3 review results

| Check | Result |
|---|---|
| Live pipeline from reconnaissance to mapping | 44 of 44 checks pass |
| Request methods received by the lab | GET and OPTIONS only |
| Forms, logout, deletion and checkout links | Never requested |
| Excluded path in plain, traversal, encoded and uppercase forms | Never requested |
| Redirects and links to unauthorized hosts | Never followed |
| DNS rebinding during a crawl | Connections stayed on the validated address |
| Cookie values and URL secrets | Not present in the database |

## Phase 4 review results

| Check | Result |
|---|---|
| Upload and validation through the running server | 28 of 29 checks pass. The oversized upload was refused, but the connection dropped, so the panel now warns first |
| Scanner output used as the only proof | Confirmation refused and audited |
| Results for unauthorized targets | Counted and never stored |
| Hostile XML, binary files and disallowed extensions | Refused |
| Credentials in scanner output and tester evidence | Masked before storage |

## Phase 6 review results

| Check | Result |
|---|---|
| Evidence upload, CVSS, remediation, retest and report generation on the running server | 32 of 32 checks pass |
| CVSS v3.1 calculator against official known-answer vectors | Exact match |
| Confirmed versus unverified findings in reports | Separated; only validated findings counted |
| Evidence and report files on disk | Stored outside the web root with 0600 permissions |
| Non-image uploaded as an image | Rejected |
| Hostile finding text in HTML and PDF reports | Escaped; PDF generation unaffected |

## Phase 5 review results

| Check | Result |
|---|---|
| Manual workspace on the running server | 25 of 25 checks pass |
| Listener on the test target during every manual workflow | No requests received |
| Network and process imports in the manual workspace | None, enforced by an automated test |
| Pasted tokens, cookies and passwords | Not stored |
| Password entered as a credential reference | Refused |

## Untrusted file parsing

Uploaded scanner reports and the imported CWE catalog XML are parsed with defusedxml (external entities
and entity expansion are rejected), elements are matched by local name, and every extracted field is
length-bounded. The CWE catalog is imported from a file you provide; the platform makes no outbound
request to fetch it.

## Non-intrusive automation

The assessment orchestrator and passive review automate only non-intrusive techniques: reconnaissance,
read-only mapping and analysis of already-collected data. They send no attack payloads and launch no
exploit tools, every target passes the scope gate before each request, and all results are unverified
until a tester validates them. Automated methodology coverage marks cases in-progress, never as passed.

## Known limitations

- **CVSS version.** The calculator computes CVSS v3.1 base scores. A CVSS v4.0 vector can be stored on a finding
  but its numeric score is not computed, because that needs the official v4.0 lookup table.
- **Report inputs.** Reports present what is stored. They do not re-test or re-verify findings at generation time.
- **Evidence retention.** A retention date is recorded on each item; automatic deletion is not yet scheduled.
- **Tester-reported results.** Workflow and authorization matrix results are what the tester records. The
  platform does not independently verify them.
- **Analyzers are indicators.** Offline analyzers review only the text supplied and do not prove exploitability.
- **Sample report formats.** Importers were tested with sample files built to each tool's documented format,
  not with output from live scans. Check the first real report from each tool.
- **Original uploads.** The uploaded file is kept unmodified in `instance/imports/` with owner-only access and
  may contain secrets. It is not included in database backups.
- **Unauthenticated crawling.** The crawler maps what is reachable without signing in. Protected pages are
  identified, but their contents are not explored.
- **JavaScript is not executed.** Routes are found by reading scripts, so pages built entirely in the
  browser may be incomplete.
- **Unsafe-link filter.** Links are skipped based on their wording. This is deliberately cautious, so some
  harmless pages are not crawled, and a state-changing GET link with an innocuous name cannot be recognized.
- **Network egress.** Scope is enforced by the platform before a tool starts. The operating system does
  not yet block a tool's traffic, and tools run as the platform's user without a network namespace.
  This hardening is planned for Phase 7.
- **DNS changes during a run.** Nmap scans the validated IP address. httpx, WhatWeb, ffuf, sslscan and
  Katana resolve the hostname themselves, so a change in the moments after the check is not caught.
- **CIDR scope.** Ranges are not swept automatically. Individual hosts must be known or listed.
- **Crawl exclusions.** Katana's crawl is limited by a path filter, and has not been run live here.

- **Audit truncation.** Deleting the newest audit rows leaves a valid chain. Each entry hash is also
  written to `instance/logs/platform.log`; ship that log off the host to detect truncation.
- **Local administrator access.** Someone with both the database and `.env` can forge audit entries.
  Keep the host itself restricted.
- **Rate limiting.** The default limiter counts per Gunicorn worker. Set `PTP_RATELIMIT_STORAGE` to
  Redis for an exact shared limit. Account lockout is enforced in the database regardless.
- **No platform MFA.** Multi-factor sign-in to the platform is not implemented.

## Reporting and handling secrets

Rotate `PTP_SECRET_KEY` to sign out all users. Do not rotate `PTP_AUDIT_KEY` casually: existing audit
entries will fail verification under a new key.
