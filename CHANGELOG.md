# Changelog

## 0.6.4 - 2026-11-19 - Automated jobs always produce findings

### Changed
- Every reconnaissance and application-mapping job now ends with the passive findings step, turning
  its collected data into unverified candidate findings automatically (when the engagement authorizes
  passive reconnaissance). Previously only the one-click Full assessment did this.

### Scope
- Unchanged: this is non-intrusive and sends no attack payloads. Findings stay unverified until a tester validates them.

## 0.6.3 - 2026-11-19 - Assessment orchestrator and more automated coverage

### Added
- "Full assessment" one-click action (`/recon/engagements/<id>/assess`) that chains every available
  non-intrusive technique — reconnaissance, application mapping and passive analysis — into one job,
  automatically creating unverified candidate findings.
- The HTTP probe now captures response security headers, and passive review raises candidates for
  missing HSTS/CSP/clickjacking/nosniff protections, directory listings and unauthenticated
  administrative or diagnostic endpoints.
- Running an automated module records methodology coverage: the WSTG/API test cases it covers are
  marked in-progress (automated) with a note, without overriding a tester's own result.

### Scope
- All of this is non-intrusive: it sends no attack payloads and launches no exploit tools. Findings
  remain unverified until a tester validates them.

## 0.6.2 - 2026-11-19 - CWE reference and recommended test procedures

### Added
- Bundled CWE reference for the 50 weaknesses the taxonomy maps to, each with a description, a
  recommended testing procedure and a mitigation. Seeded by `flask ptp seed` (migration `0007`).
- The reference appears on each finding (by CWE id) and as entries in the Test Case Library.
- `flask ptp import-cwe <file>` and `scripts/import_cwe.sh` import MITRE's official CWE catalog XML
  to enrich the reference. Detection Methods become the recommended test procedure.

### Security
- The catalog parser uses defusedxml (XXE and entity-expansion safe) and matches elements by local
  name to stay robust across CWE schema versions; all fields are length-bounded.

## 0.6.1 - 2026-11-19 - Custom test cases and findings from the library

### Added
- `flask ptp import-testcases <file>` and `scripts/import_testcases.sh` to import custom test cases from a
  JSON (or YAML) file into the library. See `docs/testcases.example.json`.
- "Create a finding from this test case" on each test case page: logs a manual finding pre-linked to the case,
  carrying its title and default severity. It still needs validation like any manual finding.

### Security
- Imported cases cannot overwrite the built-in OWASP WSTG or API Top 10 cases, and cannot claim a built-in
  framework name. Every field is validated and length-bounded, and the import is audited.

## 0.6.0 - 2026-11-18 - Phase 6: Evidence and Reporting

### Added
- Evidence repository with screenshot and file uploads, validated and stored with owner-only permissions.
- CVSS v3.1 base score calculator (exact official algorithm) that scores findings from a pasted vector.
- Remediation tracking and a retest workflow; a failed retest reopens a finding, a passed retest marks it remediated.
- HTML and PDF report generation (executive, technical, reconnaissance, attack surface, API, retest, remediation).
- Additive migration `0006` adding report metadata columns.

### Security
- Reports count only tester-validated findings as confirmed; unverified detections go in a clearly marked appendix.
- Evidence and report files are stored outside the web root with 0600 permissions and served only as attachments.
- Uploaded images are validated with Pillow; a non-image cannot masquerade as one. Text evidence is redacted.

### Fixed during the Phase 6 review
- The report image fallback caught overly broad exceptions and did not log skipped screenshots.

## 0.5.0 - 2026-11-18 - Phase 5: Manual Testing (reduced scope)

### Added
- Business logic workflows with ten test plan templates, tester-defined steps, expected outcomes and evidence.
- Authorization matrix for comparing test accounts and roles across resources.
- Offline analyzers for response headers, JSON Web Tokens and response comparison.
- Passive review that creates unverified candidates from data already collected.
- API Testing page with an API inventory and the OWASP API Security Top 10 (2023) checklist.
- Additive migration `0005` with the manual workflow and authorization matrix tables.

### Scope
- This phase sends no requests to targets. Testers perform each test themselves and record the results.

### Security
- Workflows require confirmation that only test data will be used.
- Raised findings stay unconfirmed until a tester validates them.
- Analyzer input is not stored, and tokens are never verified, altered or echoed back.

### Fixed during the Phase 5 review
- The response comparison tool now limits how many lines it processes.

## 0.4.0 - 2026-11-18 - Phase 4: Findings and Validation (reduced scope)

### Added
- OWASP WSTG v4.2 library of 97 test cases, with per-engagement methodology tracking.
- Scanner Results panel that imports Nuclei, OWASP ZAP, Burp Suite, sqlmap and generic JSON reports.
- Normalization, CWE and OWASP mapping, deduplication and correlation across detection sources.
- Findings pages, manual findings, tester evidence and a validation workflow with full history.
- Additive migration `0004` with the `finding_imports`, `finding_sources` and `finding_status_changes` tables.

### Scope
- This phase does not launch vulnerability scans or send attack payloads. Results are produced elsewhere and uploaded.

### Security
- Imported results always start unverified, and scanner output alone can never confirm a finding.
- Results for targets outside the engagement's scope are counted and discarded.
- Credentials and tokens are masked in stored evidence and URLs.

### Fixed during the Phase 4 review
- Manual findings recorded a misleading import entry in their history.
- The evidence origin constraint was missing from the migration.
- Oversized uploads ended in a dropped connection, so the panel now warns before sending them.

## 0.3.0 - 2026-11-18 - Phase 3: Application Mapping

### Added
- Built-in read-only crawler with per-request scope checks, IP pinning, rate limiting and robots.txt support.
- Discovery of links, forms, parameters, cookies, redirects, sitemaps and JavaScript API routes.
- API discovery from OpenAPI and Swagger definitions, API roots and `OPTIONS` responses.
- Detection of protected pages and categorization of endpoints by function.
- Application Mapping page with endpoint inventory, site structure, forms, parameters, cookies and endpoint relationships.
- Additive migration `0003` with the `endpoint_links`, `endpoint_parameters`, `web_forms` and `web_cookies` tables.

### Security
- The crawler can only send GET, HEAD and OPTIONS requests, and it never submits forms.
- Links that could log out, delete data or start a payment are recorded but never requested.
- Cookie values are never stored, and sensitive URL query values are redacted.

### Fixed during the Phase 3 review
- Secrets in URL query strings were stored in the endpoint inventory.
- A hostile site could record an unlimited number of links.
- A slowly sending server could hold a request open past its time limit.
- A failing module raised a logging error instead of being reported and skipped.

## 0.2.0 - 2026-11-18 - Phase 2: Reconnaissance

### Added
- Tool registry covering 21 tools, with detection, version checks, health status and install guidance.
- Least-privilege tool runner with timeouts, resource limits, cancellation and captured output.
- Database-backed job queue and background worker with live progress, pause, resume and cancel.
- Reconnaissance modules for DNS, subdomains, ports, HTTP services, technologies, TLS, content and crawling.
- Asset inventory that classifies every discovery as in or out of scope.
- Tool Management, Reconnaissance and Targets & Assets pages.
- Additive migration `0002` with the `job_events` and `tool_runs` tables.

### Security
- Every target passes the execution gate immediately before a tool touches it.
- Out-of-scope discoveries are recorded but never contacted.
- Excluded paths are removed from wordlists, so they are never requested.
- Kali wrapper scripts that could use `sudo` or raw sockets are bypassed.

### Fixed during the Phase 2 review
- Path traversal entries could pass the content discovery wordlist filter.
- Amass status messages could be stored as hostnames.
- Equivalent URLs were stored as separate services, which scanned the same site twice.
- Hidden table headers could widen pages on phones.

## 0.1.0 - 2026-11-18 - Phase 1: Foundation

### Added
- Flask application factory, blueprints, service layer and structured JSON logging.
- Complete 21-table schema with an initial Flask-Migrate revision, SQLite WAL mode and foreign keys.
- Argon2id authentication, account lockout, forced first-login password change and revocable sessions.
- Role-based access control with five default roles and object-level engagement access.
- Engagement management with lifecycle states and a recorded client authorization.
- Default-deny scope engine with canonicalization, exclusions, DNS rebinding checks and an execution gate.
- Append-only, HMAC hash-chained audit log with integrity verification.
- Dashboard with live metrics and locally hosted Bootstrap, Bootstrap Icons and Chart.js.
- REST API v1, health probes, Gunicorn configuration, setup, backup and restore scripts.

### Security
- Fixed during the Phase 1 review: credentials and query values in checked targets were written to the audit log.
- Fixed during the Phase 1 review: text typed into the username field could be logged when it was not a valid username.
- Fixed during the Phase 1 review: deeply nested URL encoding is now rejected instead of being compared.
- Fixed during the Phase 1 review: an untrusted Host header caused an unhandled 500 instead of a clean 400.
- Audit entry hashes are also written to the application log, so removal of the newest rows can be detected.
