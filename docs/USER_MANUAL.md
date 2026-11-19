# User manual

## Roles

| Role | Can do |
|---|---|
| Administrator | Everything, including users, roles and settings |
| Lead Tester | Create and run engagements, record authorization, view the audit log |
| Penetration Tester | Work on assigned engagements |
| Auditor | Read all engagements and the audit log |
| Client Viewer | Read assigned engagements |

Administrators can adjust every role except Administrator under **System Settings > Roles**.

## Running an engagement

1. **Create it.** Go to **Engagements > New engagement** and enter the client, dates, primary target,
   scope, rules of engagement, testing methods and testers.
2. **Define scope.** Put one entry per line. Anything not listed is denied.

   | Entry | Example | Covers |
   |---|---|---|
   | Domain | `app.example.com` | That exact host |
   | Wildcard | `*.dev.example.com` | Subdomains, not `dev.example.com` itself |
   | IP | `203.0.113.10` | That address |
   | CIDR | `203.0.113.0/24` | That range (IPv4 no broader than /16 by default) |
   | URL | `https://example.com/app` | That scheme, host, port and path |

   Exclusions always win. An excluded domain also excludes its subdomains.
3. **Record authorization.** On the engagement page, enter the signed document reference and client
   signatory, then confirm. This is required before testing can start.
4. **Start.** Select **Start** to make the engagement active.
5. **Check targets.** Use **Scope check** to see whether a URL, host or IP is allowed and why. It sends
   no traffic to the target. Ticking the DNS option performs a DNS lookup for in-scope hostnames.

Changing the scope, dates, methods or rules of engagement revokes the authorization and returns the
engagement to draft, because the client approved the earlier terms.

## Findings from automated jobs

Every reconnaissance and application-mapping job, not just the Full assessment, finishes by running a
passive findings step that turns the collected data into unverified candidate findings. Review them
under **Findings** (filter by "Awaiting validation"). This needs the engagement to authorize passive
reconnaissance; otherwise the job runs without the findings step.

## Full assessment (one click)

On an active, authorized engagement, use **Full assessment** (on the engagement page or Reconnaissance
list) to run every available non-intrusive technique in order — reconnaissance, application mapping and
passive analysis — as a single job. It discovers the attack surface and records unverified candidate
findings automatically. It sends no attack payloads and launches no exploit tools, so the only manual
step left is validating the findings. The job page shows progress and a live log.

Running automated modules also fills the **Testing Methodology** checklist: the test cases each module
covers are marked in-progress (automated) for a tester to confirm. Your own results are never overwritten.

## Reconnaissance

1. Make sure the engagement is active and its authorized methods include the testing you plan to run.
2. Open **Reconnaissance**, then select **New job** for the engagement.
3. Choose modules. A module is unavailable if its testing method is not authorized or its tool is missing.
4. Confirm the authorization statement and select **Start job**.
5. Watch progress and the execution log on the job page. You can pause, resume or cancel. Pausing takes
   effect after the current module finishes.

Results appear under **Targets & Assets**. Items marked **Out of scope** were discovered but never contacted.
Default limits are 10 requests per second and 25 hosts per module. Administrators can change them under
**System Settings**.

## Application mapping

1. Run reconnaissance first so all web services are known. The crawl otherwise starts from the primary target.
2. Open **Application Mapping**, choose the engagement and select **New crawl**. The engagement must authorize
   **Directory and content discovery**.
3. Set the depth and request limits, confirm the authorization statement and start the crawl.
4. Review the results in the tabs:

   | Tab | Shows |
   |---|---|
   | Endpoints | Every discovered URL, filterable by category, crawl state and protection |
   | Site structure | The application as a tree |
   | Forms | Form targets, fields, purpose and whether a CSRF token was seen |
   | Parameters | Query, form, path, header and JSON parameters |
   | Cookies | Security attributes of each cookie |

Select an endpoint to see what links to it and what it links to.

The crawl state explains why a URL was or was not requested:

| State | Meaning |
|---|---|
| Fetched | Requested successfully |
| Not requested | Known from a form, script or API definition, and left for manual testing |
| Skipped unsafe | The link could change data, such as logging out or deleting |
| Skipped robots | Disallowed by robots.txt |
| Skipped static | A binary or styling file |
| Out of scope | Outside the authorized scope, so it was never contacted |

## Uploading scanner results

Open **Vulnerability Scanner** to import results from your automated tools. This panel does not start scans.

1. Choose an engagement with recorded client authorization.
2. Select a results file of up to 10 MB and 5,000 records.
3. Leave the format on **Detect automatically**, or choose one:

   | Tool | Export to upload |
   |---|---|
   | Nuclei | JSONL or JSON output |
   | OWASP ZAP | Traditional JSON report |
   | Burp Suite | Issues exported as XML |
   | sqlmap | `results-*.csv` |
   | Any other engine | The generic JSON template linked on the page |

4. Confirm the results are covered by the authorization, then upload.

The import history shows how many results were new, correlated with an existing finding, duplicates, out of
scope or rejected. Out-of-scope results are discarded.

## Validating findings

Every imported result starts as **Unverified detection**.

1. Open **Findings** and filter by **Awaiting validation**.
2. Reproduce the issue manually within the rules of engagement.
3. Add your request and response as evidence. Passwords, tokens and cookies are masked automatically.
4. Set the status to **Confirmed** or **False positive** and explain your decision.

Scanner output alone can never confirm a finding.

## Manual testing

**Manual Testing** records testing that you carry out yourself. The platform sends no requests to targets from
this workspace.

| Tab | Use it to |
|---|---|
| Business logic | Follow a test plan, record what happened and raise a finding from any deviation |
| Authorization matrix | Compare what each test account should and did access |
| Offline analyzers | Review pasted response headers and tokens, or compare two responses |
| Passive review | Create review candidates from data the platform has already collected |

Use only test accounts, sandbox payments and client-approved test data. A finding raised here still needs validation.

## API testing

**API Testing** lists the API routes found by Application Mapping and tracks your review against the OWASP API
Security Top 10 (2023). Run **API discovery** under Application Mapping first.

## Testing methodology

### Importing custom test cases

Add your own test cases to the library from a JSON file (an object with a `test_cases` list, or a plain list).
See `docs/testcases.example.json` for the format.

```
scripts/import_testcases.sh my-testcases.json
```

Re-importing updates matching cases. The built-in OWASP WSTG and API Top 10 cases cannot be overwritten.

### CWE reference and recommended test procedures

Each finding shows a **CWE reference** panel for its CWE id, with a description, a recommended procedure
to test, a mitigation and a link to cwe.mitre.org. The same weaknesses also appear in the Test Case
Library under the CWE category. To extend the reference with the full official catalog, download the CWE
XML from <https://cwe.mitre.org/data/downloads.html>, unzip it, and run:

```
scripts/import_cwe.sh cwec_latest.xml
```

### Creating a finding from a test case

On a test case page, use **Create a finding from this test case**. Choose an authorized engagement and the
affected URL; the finding is pre-linked to the case and carries its title and default severity. It starts as a
manual finding that still needs validation.


**Test Case Library** contains all 97 OWASP WSTG v4.2 test cases and the OWASP API Security Top 10. **Testing Methodology** tracks each
engagement's result and notes for every test case, with coverage by category.

## Evidence

Each finding has an evidence section. Paste request/response text (secrets are masked automatically) or upload a
screenshot or capture. The **Evidence** page lists everything collected for an engagement. Files are stored
privately and downloaded as attachments.

## CVSS scoring

Open a finding's **Severity and scoring** panel, or the **CVSS calculator** on the Reports page. Choose the base
metrics; the score and severity are computed with the official CVSS v3.1 algorithm. Pasting a CVSS 3.1 vector into
a finding sets its score and severity automatically.

## Remediation and retesting

On a confirmed finding, record remediation status, owner and due date. Under **Retesting**, the queue lists
findings ready to retest. Record a retest result on the finding's page: a passed retest marks it remediated, and
a failed retest reopens it.

## Reports

Open **Reports**, choose an engagement with recorded authorization, pick a report type and format (PDF or HTML),
and generate. Options let you include tester evidence and screenshots, or an appendix of unverified detections.

| Report | Contents |
|---|---|
| Executive summary | Posture, risk distribution, key findings, prioritized recommendations |
| Technical | Full findings with endpoints, CVSS, CWE, OWASP, evidence and remediation |
| Reconnaissance | Discovered hosts, services and technologies |
| Attack surface | Endpoint inventory |
| API security | API inventory and API findings |
| Retest | Retest results |
| Remediation tracking | Remediation status per finding |

Every report is marked confidential, counts only tester-validated findings as confirmed, and keeps unverified
detections clearly separate.

## Credential references

Never enter passwords. Record where the credential is kept, one per line:

```
Standard user | vault://client/app/user
```

## Audit logs

**Audit Logs** lists security-relevant activity. **Verify integrity** checks that no entry has been
altered or removed from the chain.

## Coming in later phases

Sidebar items tagged `P6` show the phase that delivers them. They are not active yet.
