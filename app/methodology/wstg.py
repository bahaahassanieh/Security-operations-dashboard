"""OWASP Web Security Testing Guide v4.2 test case library.

Identifiers follow WSTG v4.2. The wording is this platform's own summary, written for testers who
are working under a signed authorization. Follow the official guide for full technique detail.
"""
from __future__ import annotations

from dataclasses import dataclass

FRAMEWORK = "OWASP WSTG"
FRAMEWORK_VERSION = "4.2"

CATEGORIES = {
    "INFO": "Information Gathering",
    "CONF": "Configuration and Deployment Management",
    "IDNT": "Identity Management",
    "ATHN": "Authentication Testing",
    "ATHZ": "Authorization Testing",
    "SESS": "Session Management",
    "INPV": "Input Validation",
    "ERRH": "Error Handling",
    "CRYP": "Cryptography",
    "BUSL": "Business Logic",
    "CLNT": "Client-Side Testing",
    "APIT": "API Testing",
}

_EVIDENCE = {
    "INFO": "Source of each observation, with the URL, response excerpt or tool output and the time it was captured.",
    "CONF": "The request and response or configuration output that shows the setting, with the affected host.",
    "IDNT": "Screens or requests for each account state tested, using only authorized test accounts.",
    "ATHN": "Request and response pairs for each attempt, with credentials and tokens redacted.",
    "ATHZ": "Paired requests for each test account or role, showing the expected and the actual access.",
    "SESS": "Request and response pairs showing token behavior over time, with token values redacted.",
    "INPV": "The minimal request and the response proving the behavior, with a harmless test value.",
    "ERRH": "The request that triggered the error and the response that shows what was disclosed.",
    "CRYP": "Tool output or captured handshake details that identify the weak protocol or algorithm.",
    "BUSL": "The workflow steps, expected outcome, actual outcome and the requests that prove the difference.",
    "CLNT": "The page, script location and browser observation that demonstrate the behavior.",
    "APIT": "The API request and response showing the behavior, with sensitive data redacted.",
}
_VALIDATION = {
    "INFO": "A tester confirms the information is real, current and useful to an attacker.",
    "CONF": "A tester reproduces the setting on the in-scope host and rules out a scanner or proxy artifact.",
    "IDNT": "A tester reproduces the behavior with test accounts and confirms it violates the intended policy.",
    "ATHN": "A tester reproduces the weakness manually and confirms the security impact on authentication.",
    "ATHZ": "A tester proves access to a resource or function that the test account should not reach.",
    "SESS": "A tester reproduces the session behavior in a clean browser profile and confirms the impact.",
    "INPV": "A tester proves server or browser behavior changed because of the input, and rules out reflection alone.",
    "ERRH": "A tester confirms the disclosed detail is genuine and is returned to an unauthenticated or low-privilege user.",
    "CRYP": "A tester confirms the weakness on the live service and that it applies to sensitive data.",
    "BUSL": "A tester reproduces the workflow in a safe environment and confirms a real business impact.",
    "CLNT": "A tester reproduces the behavior in a current browser and confirms that it is exploitable in context.",
    "APIT": "A tester reproduces the behavior against the API and confirms that it exposes data or functions.",
}


@dataclass(frozen=True)
class WstgCase:
    code: str
    title: str
    severity: str
    objective: str
    procedure: str
    expected: str
    remediation: str
    tools: tuple[str, ...]
    automation: str = "manual"

    @property
    def category(self) -> str:
        return self.code.split("-")[0]

    @property
    def test_id(self) -> str:
        return f"WSTG-{self.code}"

    @property
    def evidence(self) -> str:
        return _EVIDENCE[self.category]

    @property
    def validation(self) -> str:
        return _VALIDATION[self.category]


_B = ("Browser", "Burp Suite")
_P = ("Burp Suite", "OWASP ZAP")
_S = "semi_automated"

CASES = (
    WstgCase("INFO-01", "Search engine discovery and information leakage", "info", "Find sensitive data about the target that is already public.", "Review search engines, caches and public archives for in-scope hosts, documents and credentials.", "No sensitive internal data is publicly indexed.", "Remove exposed content, request de-indexing and limit crawler access to sensitive areas.", ("Browser",)),
    WstgCase("INFO-02", "Fingerprint web server", "info", "Identify the server type and version.", "Compare response headers, error pages and protocol behavior with known server profiles.", "Version details are not exposed unnecessarily.", "Suppress version banners and keep server software patched.", ("httpx", "WhatWeb", "Nmap"), _S),
    WstgCase("INFO-03", "Review webserver metafiles", "low", "Find paths and data exposed through metadata files.", "Review robots.txt, sitemaps, security.txt and HTML metadata for sensitive paths.", "Metafiles do not reveal private functionality.", "Protect sensitive paths with access control rather than hiding them in metafiles.", ("Application crawler", "Browser"), _S),
    WstgCase("INFO-04", "Enumerate applications on the webserver", "info", "List every application hosted on the in-scope servers.", "Review virtual hosts, non-standard ports and DNS records for additional in-scope applications.", "All hosted applications are known and intended.", "Decommission unused applications and maintain an accurate inventory.", ("Nmap", "httpx", "dig"), _S),
    WstgCase("INFO-05", "Review webpage content for information leakage", "low", "Find sensitive data in page source, comments and scripts.", "Inspect HTML comments, JavaScript and source maps for keys, credentials and internal details.", "Client content contains no secrets or internal notes.", "Strip comments and source maps from production builds and move secrets to the server.", ("Browser", "Application crawler"), _S),
    WstgCase("INFO-06", "Identify application entry points", "info", "Catalogue every way input reaches the application.", "Review mapped requests, parameters, headers, cookies and forms.", "A complete entry point inventory exists for testing.", "Document supported inputs and remove unused parameters and routes.", ("Application crawler", "Burp Suite"), _S),
    WstgCase("INFO-07", "Map execution paths through the application", "info", "Understand the workflows and paths through the application.", "Walk key workflows and record their states, branches and dependencies.", "Critical workflows are documented for coverage.", "Maintain workflow documentation and remove unreachable functionality.", ("Application crawler", "Burp Suite"), _S),
    WstgCase("INFO-08", "Fingerprint web application framework", "info", "Identify frameworks and their versions.", "Review headers, cookies, file structure and markup for framework indicators.", "Framework versions are not disclosed unnecessarily.", "Remove identifying banners and keep frameworks patched.", ("WhatWeb", "httpx"), _S),
    WstgCase("INFO-09", "Fingerprint web application", "info", "Identify the application and its components.", "Compare known files, paths and page structure with published application profiles.", "Component versions are known and supported.", "Update components and remove default files.", ("WhatWeb", "Browser"), _S),
    WstgCase("INFO-10", "Map application architecture", "info", "Understand tiers, proxies and third-party services.", "Review DNS, TLS, headers and responses for load balancers, CDNs, WAFs and back ends.", "The architecture is understood and matches documentation.", "Limit architectural disclosure and document trust boundaries.", ("Nmap", "dig", "sslscan"), _S),

    WstgCase("CONF-01", "Network infrastructure configuration", "medium", "Review supporting infrastructure for known weaknesses.", "Identify exposed services and administrative interfaces and compare versions with vendor advisories.", "Only required services are exposed and all are patched.", "Close unnecessary ports, patch services and restrict administration.", ("Nmap", "sslscan"), _S),
    WstgCase("CONF-02", "Application platform configuration", "medium", "Find insecure platform defaults.", "Review sample files, default pages, debug settings and logging behavior.", "Defaults and debug features are disabled in production.", "Apply a hardening baseline and remove sample content.", ("Browser", "Burp Suite")),
    WstgCase("CONF-03", "File extension handling", "medium", "Check how sensitive file types are served.", "Review how the server treats configuration, source and archive extensions already discovered.", "Sensitive file types are never served to clients.", "Deny sensitive extensions and keep such files outside the web root.", ("Application crawler", "ffuf"), _S),
    WstgCase("CONF-04", "Old, backup and unreferenced files", "medium", "Find forgotten files that disclose code or data.", "Review discovered content for backups, old versions and unreferenced files.", "No backup or obsolete file is reachable.", "Remove stale files and keep backups outside the web root.", ("ffuf", "Application crawler"), _S),
    WstgCase("CONF-05", "Admin interface enumeration", "medium", "Locate administrative interfaces.", "Review mapped routes and common locations, then confirm how each one is protected.", "Admin interfaces are restricted and strongly authenticated.", "Restrict admin access by network and role, and require MFA.", ("ffuf", "Application crawler"), _S),
    WstgCase("CONF-06", "HTTP methods", "medium", "Identify supported HTTP methods and their risks.", "Review advertised methods and confirm that each one is required and access-controlled.", "Only required methods are enabled.", "Disable unused methods and enforce authorization on every method.", ("Application crawler", "Burp Suite"), _S),
    WstgCase("CONF-07", "HTTP Strict Transport Security", "medium", "Confirm browsers are required to use HTTPS.", "Review the HSTS header, its lifetime and subdomain coverage on HTTPS responses.", "HSTS is present with a suitable lifetime.", "Send Strict-Transport-Security with a long max-age.", ("httpx", "Browser"), _S),
    WstgCase("CONF-08", "RIA cross-domain policy", "medium", "Review legacy cross-domain policy files.", "Inspect crossdomain.xml and clientaccesspolicy.xml for overly permissive entries.", "No permissive cross-domain policy exists.", "Remove these files or restrict them to trusted origins.", ("Browser",)),
    WstgCase("CONF-09", "File permissions", "medium", "Check permissions on sensitive server files.", "With client-approved access, review ownership and permissions of configuration and data files.", "Files follow least privilege.", "Restrict file permissions and run services with minimal rights.", ("Manual review",)),
    WstgCase("CONF-10", "Subdomain takeover", "high", "Find DNS records that point to unclaimed services.", "Review CNAME records for in-scope names that reference deprovisioned third-party services.", "Every DNS record points to a controlled resource.", "Remove dangling DNS records during service decommissioning.", ("dig", "Subfinder"), _S),
    WstgCase("CONF-11", "Cloud storage", "high", "Check access controls on cloud storage.", "Identify in-scope storage locations and review their anonymous read and write settings.", "Storage is private unless explicitly public by design.", "Apply least-privilege policies and block public access by default.", ("Browser", "Cloud provider tools")),

    WstgCase("IDNT-01", "Role definitions", "medium", "Understand the application's roles and permissions.", "Document roles with the client and compare them with observed behavior.", "Roles match the intended permission model.", "Define and review a least-privilege role matrix.", ("Burp Suite",)),
    WstgCase("IDNT-02", "User registration process", "medium", "Assess identity checks during registration.", "Using test accounts, review verification, duplicate handling and data requirements.", "Registration enforces the required identity checks.", "Verify identities according to business risk and prevent duplicate abuse.", _B),
    WstgCase("IDNT-03", "Account provisioning process", "medium", "Review who can create and remove accounts.", "Confirm which roles can provision accounts and how approvals are enforced.", "Provisioning is limited to authorized roles.", "Require approval and audit all provisioning actions.", _B),
    WstgCase("IDNT-04", "Account enumeration and guessable accounts", "medium", "Check whether valid usernames can be discovered.", "Compare responses and timing for valid and invalid test accounts across login, reset and signup.", "Responses do not reveal whether an account exists.", "Return uniform messages and uniform timing.", _B),
    WstgCase("IDNT-05", "Weak or unenforced username policy", "low", "Review how predictable usernames are.", "Review the username format and whether its structure can be predicted.", "Usernames are not easily predictable.", "Enforce a policy that avoids predictable identifiers.", ("Browser",)),

    WstgCase("ATHN-01", "Credentials transported over an encrypted channel", "high", "Confirm that credentials are always encrypted in transit.", "Observe login and credential flows for any plaintext transmission or downgrade.", "All credentials travel over TLS.", "Require HTTPS everywhere and enable HSTS.", _B),
    WstgCase("ATHN-02", "Default credentials", "high", "Find accounts that still use vendor defaults.", "Within the agreed rules, review identified products for documented default accounts.", "No default credentials remain active.", "Change defaults at deployment and disable unused accounts.", ("Browser",)),
    WstgCase("ATHN-03", "Weak lockout mechanism", "medium", "Evaluate protection against repeated login attempts.", "Using a dedicated test account and agreed limits, observe lockout thresholds and recovery.", "Repeated failures trigger lockout or throttling.", "Apply throttling, lockout and monitoring.", _B),
    WstgCase("ATHN-04", "Bypassing authentication schema", "critical", "Check whether protected functions can be reached without login.", "Request protected resources directly and review whether each one enforces authentication.", "Every protected resource requires a valid session.", "Enforce authentication centrally on the server.", _B),
    WstgCase("ATHN-05", "Vulnerable remember password", "medium", "Review how remembered logins are stored.", "Inspect persistent tokens for lifetime, storage location and revocation.", "Remember-me tokens are random, revocable and protected.", "Use random server-validated tokens and never store passwords on the client.", _B),
    WstgCase("ATHN-06", "Browser cache weaknesses", "medium", "Check whether sensitive pages remain in browser caches.", "Review cache headers on sensitive pages and behavior after logout.", "Sensitive responses are not cached.", "Send Cache-Control: no-store on sensitive responses.", _B),
    WstgCase("ATHN-07", "Weak password policy", "medium", "Evaluate password strength requirements.", "Review the length, complexity, reuse and breached-password rules with a test account.", "The policy meets current guidance.", "Follow NIST SP 800-63B and block known-breached passwords.", ("Browser",)),
    WstgCase("ATHN-08", "Weak security questions", "medium", "Assess security questions used for recovery.", "Review whether questions have guessable or publicly discoverable answers.", "Security questions are not relied on for recovery.", "Replace security questions with stronger recovery factors.", ("Browser",)),
    WstgCase("ATHN-09", "Weak password change or reset", "high", "Evaluate password change and reset flows.", "Using test accounts, review token randomness, expiry, reuse and re-authentication.", "Reset tokens are single-use, short-lived and unguessable.", "Use strong expiring tokens and require the current password for changes.", _B),
    WstgCase("ATHN-10", "Weaker authentication in alternative channels", "high", "Compare authentication across all channels.", "Compare web, mobile, API and legacy channels for weaker controls.", "All channels enforce equivalent authentication.", "Apply one authentication standard across every channel.", _B),

    WstgCase("ATHZ-01", "Directory traversal and file include", "high", "Check whether file parameters can reach unintended files.", "Review parameters that reference files and confirm that access stays within the intended directory.", "File access is limited to the permitted location.", "Use allow-lists of identifiers and canonicalize paths on the server.", _P, _S),
    WstgCase("ATHZ-02", "Bypassing authorization schema", "high", "Check whether roles can reach functions outside their permissions.", "Replay each role's requests using a lower-privilege test account and compare results.", "Every function enforces server-side authorization.", "Deny by default and enforce authorization centrally.", _B),
    WstgCase("ATHZ-03", "Privilege escalation", "critical", "Check whether a user can gain higher privileges.", "Review role-bearing parameters and privileged functions with low-privilege test accounts.", "Users cannot change their own privileges.", "Derive roles on the server and validate every privileged action.", _B),
    WstgCase("ATHZ-04", "Insecure direct object references", "high", "Check ownership enforcement on object identifiers.", "Using two test accounts, request one account's objects with the other's session.", "Users can only reach objects they own.", "Validate object ownership on every request.", _B),

    WstgCase("SESS-01", "Session management schema", "high", "Assess how session tokens are created and handled.", "Collect tokens from test logins and review their randomness, length and structure.", "Tokens are long, random and opaque.", "Use the framework's vetted session management.", _B),
    WstgCase("SESS-02", "Cookie attributes", "medium", "Review the security attributes of cookies.", "Review Secure, HttpOnly, SameSite, Domain, Path and lifetime for each cookie.", "Session cookies carry all appropriate attributes.", "Set Secure, HttpOnly and SameSite with a narrow scope.", ("Application crawler", "Browser"), _S),
    WstgCase("SESS-03", "Session fixation", "high", "Check whether the session identifier changes at login.", "Compare the session identifier before and after authentication with a test account.", "A new identifier is issued after login.", "Regenerate the session identifier whenever privilege changes.", _B),
    WstgCase("SESS-04", "Exposed session variables", "medium", "Check whether session tokens leak.", "Review URLs, logs, referrers and caching for session token exposure.", "Tokens are only sent in protected cookies or headers.", "Never place session tokens in URLs.", _B),
    WstgCase("SESS-05", "Cross-site request forgery", "high", "Check that state-changing requests prove user intent.", "Review state-changing requests for anti-CSRF tokens and SameSite protections.", "State-changing requests are bound to the user's session.", "Use synchronizer tokens and SameSite cookies.", ("Application crawler", "Burp Suite"), _S),
    WstgCase("SESS-06", "Logout functionality", "medium", "Confirm logout ends the session on the server.", "Sign out with a test account and confirm the old session no longer works.", "Sessions are invalidated on the server at logout.", "Destroy server-side session state at logout.", _B),
    WstgCase("SESS-07", "Session timeout", "medium", "Confirm inactive sessions expire.", "Leave a test session idle and confirm that it expires as specified.", "Idle and absolute timeouts are enforced on the server.", "Apply risk-appropriate idle and absolute timeouts.", _B),
    WstgCase("SESS-08", "Session puzzling", "medium", "Check whether session variables are reused across contexts.", "Review flows that store values in the session and whether another flow trusts them.", "Session values cannot bypass workflow checks.", "Scope session values to their flow and validate them at use.", _B),
    WstgCase("SESS-09", "Session hijacking", "high", "Assess exposure of active sessions to interception.", "Review whether session cookies can be sent over unencrypted connections.", "Session tokens are protected throughout their life.", "Require TLS everywhere, Secure cookies and HSTS.", _B),

    WstgCase("INPV-01", "Reflected cross-site scripting", "high", "Check whether input is reflected without safe encoding.", "Trace parameters into responses using harmless markers and review the output encoding.", "Output is encoded for its context.", "Apply contextual output encoding and a strict CSP.", _P, _S),
    WstgCase("INPV-02", "Stored cross-site scripting", "high", "Check whether stored input is rendered unsafely.", "Store harmless markers in test records and review how each view renders them.", "Stored data is encoded when displayed.", "Encode on output and sanitize rich content with a vetted library.", _P, _S),
    WstgCase("INPV-03", "HTTP verb tampering", "medium", "Check whether controls depend on the HTTP method.", "Compare authorization and behavior across the methods a route accepts.", "Controls apply consistently to all methods.", "Allow only required methods and enforce checks for each.", _B),
    WstgCase("INPV-04", "HTTP parameter pollution", "medium", "Check how duplicate parameters are handled.", "Review how each tier interprets repeated parameters.", "Duplicate parameters are handled consistently.", "Reject or consistently normalize duplicate parameters.", _B),
    WstgCase("INPV-05", "SQL injection", "critical", "Check whether input alters database queries.", "Review data-driven parameters with non-destructive test values and compare the responses.", "Input never changes query structure.", "Use parameterized queries and least-privilege database accounts.", _P, _S),
    WstgCase("INPV-06", "LDAP injection", "high", "Check whether input alters directory queries.", "Review directory-backed searches and logins for unsafe query construction.", "Directory queries treat input as data.", "Escape LDAP special characters and use safe query APIs.", _B),
    WstgCase("INPV-07", "XML injection", "high", "Check how XML input is parsed.", "Review XML-accepting endpoints and confirm that external entities are disabled.", "Parsers reject external entities and unsafe structures.", "Disable DTDs and external entities in every XML parser.", _B),
    WstgCase("INPV-08", "Server-side includes injection", "high", "Check whether input reaches SSI processing.", "Identify SSI-enabled pages and review how user input is written into them.", "User input is never processed as a directive.", "Disable SSI where it is not needed and encode input.", _B),
    WstgCase("INPV-09", "XPath injection", "high", "Check whether input alters XPath queries.", "Review XML-backed lookups for unsafe query construction.", "XPath queries treat input as data.", "Use parameterized XPath or strict input validation.", _B),
    WstgCase("INPV-10", "IMAP and SMTP injection", "high", "Check whether input reaches mail commands.", "Review mail features for unsafe handling of line breaks and commands.", "Mail features reject control characters.", "Validate mail input and use safe mail libraries.", _B),
    WstgCase("INPV-11", "Code injection", "critical", "Check whether input can be evaluated as code.", "Review features that evaluate or dynamically include content, with client approval.", "User input is never executed as code.", "Avoid dynamic evaluation and use strict allow-lists.", _B),
    WstgCase("INPV-12", "Command injection", "critical", "Check whether input reaches operating system commands.", "Identify features that call system utilities, and review their handling of input with client approval.", "Input never reaches a shell.", "Use safe APIs with argument arrays and never build shell strings.", _B),
    WstgCase("INPV-13", "Format string injection", "high", "Check whether input is used as a format string.", "Review logging and formatting features for unsafe use of user input.", "User input is never used as a format string.", "Use constant format strings.", _B),
    WstgCase("INPV-14", "Incubated vulnerabilities", "high", "Check whether stored input causes later harm.", "Review how stored test data is processed by other users, jobs and integrations.", "Stored data stays safe in every later context.", "Validate at input and encode for each later use.", _B),
    WstgCase("INPV-15", "HTTP splitting and smuggling", "high", "Check for request and response desynchronization.", "With client approval and low traffic, review how front-end and back-end servers parse requests.", "All tiers parse HTTP messages consistently.", "Normalize requests, reject ambiguity and use HTTP/2 end to end.", _B),
    WstgCase("INPV-16", "HTTP incoming requests", "low", "Review the traffic the application receives and sends.", "Monitor requests during normal use for unexpected or sensitive traffic.", "Traffic matches the documented behavior.", "Remove unnecessary calls and protect sensitive traffic.", _P),
    WstgCase("INPV-17", "Host header injection", "medium", "Check whether the application trusts the Host header.", "Review features that build links from the Host header, such as password reset.", "Only configured hostnames are accepted.", "Validate the Host header against an allow-list.", _B),
    WstgCase("INPV-18", "Server-side template injection", "critical", "Check whether input is evaluated by a template engine.", "Review templated features with harmless markers and confirm that input stays literal.", "Input is passed to templates only as data.", "Never build templates from user input, and sandbox the engine.", _B),
    WstgCase("INPV-19", "Server-side request forgery", "high", "Check whether the server can be made to fetch arbitrary URLs.", "Review URL-accepting features using only an approved callback host.", "Server-side requests go only to allow-listed destinations.", "Allow-list destinations and block internal address ranges.", _B),

    WstgCase("ERRH-01", "Improper error handling", "medium", "Check what error responses reveal.", "Review error pages from invalid requests for internal details.", "Errors are generic and logged on the server.", "Return generic errors and log the details on the server.", _B),
    WstgCase("ERRH-02", "Stack traces", "medium", "Check whether stack traces reach users.", "Review error responses for stack traces and debug output.", "Stack traces are never shown to users.", "Disable debug output in production.", _B),

    WstgCase("CRYP-01", "Weak transport layer security", "high", "Assess TLS protocols, ciphers and certificates.", "Review supported protocols, cipher suites and certificate validity.", "Only modern TLS configurations are accepted.", "Disable legacy protocols and weak ciphers, and keep certificates valid.", ("sslscan", "testssl.sh"), _S),
    WstgCase("CRYP-02", "Padding oracle", "high", "Check whether decryption errors reveal information.", "Review how encrypted values are validated and whether errors differ.", "Decryption failures are indistinguishable.", "Use authenticated encryption such as AES-GCM.", _B),
    WstgCase("CRYP-03", "Sensitive information over unencrypted channels", "high", "Find sensitive data sent without encryption.", "Review traffic for sensitive data sent over HTTP or other cleartext channels.", "Sensitive data is always encrypted in transit.", "Require TLS for all sensitive communication.", _B),
    WstgCase("CRYP-04", "Weak encryption", "high", "Find weak cryptographic algorithms and practices.", "Review algorithms, key sizes and hashing in observed tokens and available design details.", "Only current algorithms are used.", "Use vetted libraries, modern algorithms and proper key management.", _B),

    WstgCase("BUSL-01", "Business logic data validation", "high", "Check that data is valid for the business process.", "Define expected outcomes and review workflows with logically invalid test data.", "The server enforces business rules.", "Validate business rules on the server at every step.", _B),
    WstgCase("BUSL-02", "Ability to forge requests", "high", "Check whether hidden or predictable values can be altered.", "Review hidden fields and workflow parameters in a non-production-safe manner agreed with the client.", "The server does not trust client-supplied workflow values.", "Derive sensitive values on the server.", _B),
    WstgCase("BUSL-03", "Integrity checks", "high", "Check protection of data that users should not change.", "Compare what each role can modify with what the interface permits.", "Protected data cannot be modified by users.", "Enforce integrity checks on the server and audit changes.", _B),
    WstgCase("BUSL-04", "Process timing", "medium", "Check whether timing can be abused.", "Review time-limited workflows and race-sensitive steps with test data and client approval.", "Workflows are safe under timing variation.", "Use transactions, locks and server-side time limits.", _B),
    WstgCase("BUSL-05", "Function use limits", "medium", "Check limits on how often functions can be used.", "Review single-use and limited functions with test accounts, without real transactions.", "Limits are enforced on the server.", "Track and enforce usage limits on the server.", _B),
    WstgCase("BUSL-06", "Circumvention of work flows", "high", "Check whether required workflow steps can be skipped.", "Attempt steps out of order in a test workflow and compare outcomes.", "Each step verifies that earlier steps were completed.", "Maintain workflow state on the server.", _B),
    WstgCase("BUSL-07", "Defenses against application misuse", "medium", "Assess detection of and response to misuse.", "Review with the client whether suspicious activity is detected and acted on.", "Misuse is detected, logged and limited.", "Add monitoring, rate limiting and alerting.", _B),
    WstgCase("BUSL-08", "Upload of unexpected file types", "medium", "Check enforcement of allowed upload types.", "Upload harmless test files of unexpected types and review how they are handled.", "Only approved file types are accepted.", "Validate type, extension and content on the server.", _B),
    WstgCase("BUSL-09", "Upload of malicious files", "high", "Check defenses against harmful uploads.", "Use industry-standard harmless test files, such as the EICAR test file, with client approval.", "Harmful files are blocked and stored safely.", "Scan uploads, store them outside the web root and serve them safely.", _B),

    WstgCase("CLNT-01", "DOM-based cross-site scripting", "high", "Check for unsafe data flows in browser scripts.", "Trace URL and storage sources into dangerous DOM sinks.", "Client scripts use safe DOM APIs.", "Use textContent, safe sinks and Trusted Types.", ("Browser", "Burp Suite")),
    WstgCase("CLNT-02", "JavaScript execution", "high", "Check whether input can run as script in the page.", "Review features that insert user-controlled values into scripts.", "User input never runs as script.", "Avoid dynamic script construction and apply a strict CSP.", ("Browser",)),
    WstgCase("CLNT-03", "HTML injection", "medium", "Check whether input can alter page markup.", "Trace user-controlled values into the DOM with harmless markup.", "Input cannot change page structure.", "Encode output and sanitize permitted HTML.", ("Browser",)),
    WstgCase("CLNT-04", "Client-side URL redirect", "medium", "Check for redirects controlled by users.", "Review scripts and parameters that set navigation targets.", "Redirects go only to approved destinations.", "Allow-list redirect targets.", ("Browser",)),
    WstgCase("CLNT-05", "CSS injection", "medium", "Check whether input can alter stylesheets.", "Trace user-controlled values into style contexts.", "Input cannot alter styles.", "Encode for CSS contexts and restrict style sources with CSP.", ("Browser",)),
    WstgCase("CLNT-06", "Client-side resource manipulation", "medium", "Check whether input controls loaded resources.", "Review scripts that load resources from user-controlled paths.", "Resource locations cannot be set by users.", "Allow-list resource locations.", ("Browser",)),
    WstgCase("CLNT-07", "Cross-origin resource sharing", "high", "Review the CORS policy.", "Review CORS response headers for reflected origins and credentialed access.", "Only trusted origins are allowed.", "Allow-list exact origins and avoid credentials with broad policies.", _B),
    WstgCase("CLNT-08", "Cross-site flashing", "low", "Review legacy Flash content.", "Identify any remaining Flash files and confirm that they are removed.", "No Flash content remains.", "Remove legacy Flash content.", ("Browser",)),
    WstgCase("CLNT-09", "Clickjacking", "medium", "Check whether pages can be framed by other sites.", "Review X-Frame-Options and CSP frame-ancestors on sensitive pages.", "Sensitive pages cannot be framed.", "Set CSP frame-ancestors and X-Frame-Options.", ("Browser", "httpx"), _S),
    WstgCase("CLNT-10", "WebSockets", "high", "Assess WebSocket authentication and validation.", "Review origin checks, authentication and message authorization.", "WebSockets enforce origin, authentication and authorization.", "Validate the origin and authorize every message.", _B),
    WstgCase("CLNT-11", "Web messaging", "medium", "Review postMessage handling.", "Review message listeners for origin validation and unsafe data use.", "Message handlers validate origin and content.", "Check event.origin and treat message data as untrusted.", ("Browser",)),
    WstgCase("CLNT-12", "Browser storage", "medium", "Check for sensitive data in browser storage.", "Review localStorage, sessionStorage and IndexedDB during authenticated use.", "Sensitive data is not stored in the browser.", "Keep secrets out of web storage.", ("Browser",)),
    WstgCase("CLNT-13", "Cross-site script inclusion", "medium", "Check whether sensitive data is exposed through scripts.", "Review authenticated script responses for sensitive data.", "Scripts contain no user-specific secrets.", "Serve sensitive data as protected JSON, not as script.", _B),

    WstgCase("APIT-01", "GraphQL", "high", "Assess GraphQL exposure and authorization.", "Review schema exposure, field-level authorization and query limits with test accounts.", "The schema is protected and every resolver enforces authorization.", "Disable introspection in production, authorize resolvers and limit query cost.", _B),
)
