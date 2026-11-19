# Integrated security tools

Run detection at any time with **Tool Management > Detect tools**, or:

```bash
FLASK_APP=wsgi:app .venv/bin/flask ptp tools
```

The platform never assumes a tool is installed. A missing tool is reported with its install command,
and modules that need it are blocked or skipped.

## Reconnaissance tools in use

| Module | Tool | Authorized method required | How it is run |
|---|---|---|---|
| DNS records | dig | Passive reconnaissance | A, AAAA, CNAME, MX, NS and TXT lookups |
| Subdomain discovery | Subfinder, Amass | Passive reconnaissance | Passive sources only, for wildcard-scoped domains |
| Port and service scan | Nmap | Port and service scanning | Unprivileged TCP connect scan, no NSE scripts, validated IP pinned |
| HTTP service discovery | httpx-toolkit | Active reconnaissance | Redirects never followed |
| Technology fingerprinting | WhatWeb | Active reconnaissance | Aggression level 1, redirects never followed |
| TLS inspection | sslscan | Active reconnaissance | Protocols, weak ciphers and certificates |
| Directory and file discovery | ffuf | Directory and content discovery | No recursion or redirects, excluded paths removed from the wordlist |
| Endpoint crawl | Katana | Directory and content discovery | Depth 2, same host only |

## Built-in crawler

Application Mapping uses the platform's own read-only crawler, so it works without Katana. Katana remains an
optional reconnaissance module.

## Validation status

| Tool | Status |
|---|---|
| dig, Nmap, httpx-toolkit, WhatWeb, sslscan, ffuf | Run for real against a local lab |
| Subfinder, Amass | Detection and result handling tested. Not run live, because that needs a domain you are authorized to enumerate |
| Katana | Not installed here. Result handling is tested with sample output |

## Kali-specific behavior

| Path | Why the platform handles it specially |
|---|---|
| `/usr/bin/amass` | This wrapper can call `sudo`, so `/usr/lib/amass/amass` is run directly |
| `/usr/bin/nmap` | This wrapper adds `--privileged`, so `/usr/lib/nmap/nmap --unprivileged` is run directly |
| `/usr/bin/httpx` | This is an unrelated Python client, so only `httpx-toolkit` is used |

## Scanner result import

Reports from Nuclei, OWASP ZAP, Burp Suite and sqlmap can be uploaded on the Vulnerability Scanner page, along
with any other engine's results in the generic JSON format. The platform does not run these scanners.

## Detected only

Nuclei, sqlmap, Dalfox, JWT Tool, Commix, testssl.sh, OWASP ZAP, Burp Suite (optional), Semgrep, Trivy,
Retire.js and OWASP Dependency-Check are detected and reported. The platform does not execute them.

## Execution safeguards

- Tools run from fixed definitions. No page, API call or database value can change which program runs.
- Commands are argument arrays. A shell is never used.
- Each run gets a private directory, a minimal environment without platform secrets, a timeout and an
  output size limit. Cancelling or timing out stops the tool and all its child processes.
- A binary is refused if other users can modify it.
- All tool output is treated as hostile: it is size-limited, parsed safely and escaped when displayed.
