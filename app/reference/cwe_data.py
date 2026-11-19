"""Curated CWE reference bundled with the platform.

Covers the CWE identifiers the vulnerability taxonomy maps to. Each entry carries the official CWE
name, a short description, a recommended (non-destructive) testing procedure, and a mitigation. The
full catalog can be imported on top of this with ``flask ptp import-cwe``.

Each value is (name, description, recommended_test, mitigation).
"""
from __future__ import annotations

BUNDLED: dict[str, tuple[str, str, str, str]] = {
    "CWE-22": (
        "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "The application uses externally supplied input to build a file path without restricting it to an intended directory.",
        "With a test account, submit a known filename in each file-referencing parameter, then a traversal sequence toward a benign file outside the intended directory, and compare the responses to see whether access escapes the directory.",
        "Resolve and canonicalize paths on the server and confirm they stay within an allow-listed base directory; prefer opaque identifiers over filenames.",
    ),
    "CWE-23": (
        "Relative Path Traversal",
        "The application does not neutralize relative path sequences such as '..' that can traverse outside a restricted directory.",
        "Supply relative sequences ('../') in file parameters toward a harmless target and observe whether the server resolves them outside the intended directory.",
        "Canonicalize the path and verify it is within the permitted directory; reject any input containing path separators or traversal sequences.",
    ),
    "CWE-35": (
        "Path Traversal: '.../...//'",
        "The application removes a single traversal sequence but not collapsed or doubled sequences, so filtering can be bypassed.",
        "Send doubled or collapsed traversal variants ('.../...//', encoded forms) toward a benign target and check whether a single-pass filter was bypassed.",
        "Canonicalize fully before validation rather than stripping sequences once; validate the final resolved path against an allow-list.",
    ),
    "CWE-77": (
        "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
        "User input is incorporated into a command that the application executes, allowing the command to be altered.",
        "With client approval, add benign command separators or a harmless time-delay to parameters that reach a command and look for a change in timing or output; never run destructive commands.",
        "Avoid invoking commands with user input; use safe APIs with argument arrays and strict allow-lists, never a shell string.",
    ),
    "CWE-78": (
        "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "User input reaches an operating-system command, allowing attacker-controlled commands to run.",
        "On features that call system utilities, inject a benign separator or an approved out-of-band/time-delay marker and observe a behavioral change; keep payloads non-destructive and client-approved.",
        "Use library calls instead of shell commands, pass arguments as an array, and validate input against a strict allow-list.",
    ),
    "CWE-79": (
        "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "The application places untrusted input into a web page without safe output encoding, letting scripts run in a victim's browser.",
        "Insert a unique harmless marker into each parameter and stored field, then inspect the HTML and DOM to see whether it is reflected or stored without context-appropriate encoding.",
        "Apply contextual output encoding, sanitize rich content with a vetted library, and deploy a strict Content Security Policy.",
    ),
    "CWE-80": (
        "Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)",
        "The application does not neutralize basic script-related tags such as <script> in user input.",
        "Submit harmless markup containing basic tags and confirm whether it renders as HTML rather than text in the response.",
        "Encode output for its context and restrict allowed HTML with a sanitizer.",
    ),
    "CWE-89": (
        "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "User input is incorporated into an SQL query without proper neutralization, allowing the query structure to be altered.",
        "For each data-driven parameter, compare responses to a true and a false logical condition and to a benign syntax-breaking character; confirm behavior changes without running destructive statements.",
        "Use parameterized queries or prepared statements and least-privilege database accounts; never concatenate input into SQL.",
    ),
    "CWE-90": (
        "Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')",
        "User input alters the meaning of an LDAP query because special characters are not neutralized.",
        "In directory-backed search or login fields, submit LDAP metacharacters and compare results to a baseline for changes in matched entries.",
        "Escape LDAP special characters and use safe query-building APIs with input validation.",
    ),
    "CWE-93": (
        "Improper Neutralization of CRLF Sequences ('CRLF Injection')",
        "The application does not neutralize carriage-return/line-feed sequences, allowing injection into line-based protocols.",
        "Insert encoded CRLF sequences into parameters reflected in headers or logs and observe whether new lines or header fields appear.",
        "Strip or reject CR and LF characters from values used in headers, logs and other line-oriented contexts.",
    ),
    "CWE-94": (
        "Improper Control of Generation of Code ('Code Injection')",
        "Untrusted input influences code that the application subsequently evaluates or executes.",
        "On features that evaluate or dynamically include content, submit a benign expression and observe whether it is evaluated; obtain client approval and avoid destructive payloads.",
        "Avoid dynamic evaluation of input; where unavoidable, use strict allow-lists and sandboxing.",
    ),
    "CWE-98": (
        "Improper Control of Filename for Include/Require Statement ('PHP Remote/Local File Inclusion')",
        "A filename used in an include/require statement is controlled by input, allowing inclusion of attacker-chosen files.",
        "Point include-style parameters at a known local resource and at a benign alternate path to see whether the included file changes; do not reference remote hosts outside scope.",
        "Use a fixed allow-list of includable files and never build include paths from user input.",
    ),
    "CWE-113": (
        "Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')",
        "Input placed into HTTP response headers is not neutralized, allowing header or response splitting.",
        "Submit encoded CRLF in values reflected into response headers (such as redirect locations) and check whether an injected header appears.",
        "Reject CR/LF in header values and use framework APIs that encode header output.",
    ),
    "CWE-200": (
        "Exposure of Sensitive Information to an Unauthorized Actor",
        "The application discloses sensitive information to an actor that is not authorized to access it.",
        "Review responses, errors, comments and API payloads for sensitive data, comparing what each test role should and does receive.",
        "Return only the data each role needs, and classify and protect sensitive fields server-side.",
    ),
    "CWE-209": (
        "Generation of Error Message Containing Sensitive Information",
        "Error messages reveal internal details such as stack traces, queries or paths.",
        "Trigger invalid input and error conditions and inspect the responses for stack traces, framework details or internal paths.",
        "Return generic error messages to clients and log the details on the server only.",
    ),
    "CWE-285": (
        "Improper Authorization",
        "The application does not correctly check whether an actor is authorized to perform a requested action.",
        "Using two test accounts of differing privilege, replay each privileged request as the lower-privilege account and confirm access is refused.",
        "Enforce authorization on the server for every request and deny by default.",
    ),
    "CWE-287": (
        "Improper Authentication",
        "The application does not adequately verify the identity of an actor.",
        "Exercise login, token and recovery flows with test accounts, looking for ways to authenticate without valid credentials or to reuse captured tokens.",
        "Use standard, well-tested authentication with strong validation of every credential and token.",
    ),
    "CWE-306": (
        "Missing Authentication for Critical Function",
        "A critical function can be reached without any authentication.",
        "Request sensitive endpoints and functions directly without a session and confirm whether authentication is enforced.",
        "Require authentication centrally on the server for every sensitive function.",
    ),
    "CWE-319": (
        "Cleartext Transmission of Sensitive Information",
        "Sensitive information is transmitted without encryption and can be intercepted.",
        "Observe whether credentials, tokens or sensitive data are ever sent over HTTP or another cleartext channel, including downgrade paths.",
        "Require TLS for all sensitive communication and enable HSTS.",
    ),
    "CWE-326": (
        "Inadequate Encryption Strength",
        "The application uses an encryption scheme that is weaker than the sensitivity of the data requires.",
        "Review supported TLS protocols, key sizes and cipher suites with a TLS scanner and confirm no weak configurations are accepted.",
        "Allow only modern protocols, strong ciphers and adequate key sizes.",
    ),
    "CWE-327": (
        "Use of a Broken or Risky Cryptographic Algorithm",
        "The application uses a cryptographic algorithm that is broken or otherwise risky.",
        "Identify algorithms in use from tokens, handshakes and available design details, and flag any deprecated or broken primitives.",
        "Use vetted libraries and current algorithms with proper key management.",
    ),
    "CWE-347": (
        "Improper Verification of Cryptographic Signature",
        "The application does not verify, or incorrectly verifies, a cryptographic signature.",
        "For signed tokens (such as JWTs), test whether altered payloads, the 'none' algorithm or wrong keys are accepted by the server.",
        "Verify signatures with a trusted key and algorithm, and reject unsigned or mismatched tokens.",
    ),
    "CWE-352": (
        "Cross-Site Request Forgery (CSRF)",
        "The application does not verify that a state-changing request was intentionally made by the user.",
        "Review state-changing requests for an anti-CSRF token and SameSite protection; confirm a request without the token is rejected.",
        "Use synchronizer tokens and SameSite cookies on state-changing requests.",
    ),
    "CWE-434": (
        "Unrestricted Upload of File with Dangerous Type",
        "The application allows uploading files of dangerous types without sufficient restriction.",
        "Upload benign test files of unexpected types and, with approval, an industry-standard harmless test file, and observe how each is validated, stored and served.",
        "Validate type, extension and content, store uploads outside the web root, and serve them safely.",
    ),
    "CWE-444": (
        "Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')",
        "Front-end and back-end servers interpret HTTP requests differently, allowing request boundaries to be desynchronized.",
        "With client approval and minimal traffic, probe how front-end and back-end servers parse ambiguous Content-Length/Transfer-Encoding combinations.",
        "Normalize requests, reject ambiguous framing, and use HTTP/2 end to end where possible.",
    ),
    "CWE-497": (
        "Exposure of Sensitive System Information to an Unauthorized Control Sphere",
        "The application exposes system information such as configuration or environment details.",
        "Review responses, headers and status pages for system, environment or configuration disclosure.",
        "Suppress system details in responses and restrict diagnostic endpoints.",
    ),
    "CWE-502": (
        "Deserialization of Untrusted Data",
        "The application deserializes untrusted data without sufficient validation.",
        "Identify endpoints that accept serialized objects and review, with client approval, whether tampered but benign serialized data changes behavior.",
        "Avoid deserializing untrusted data; use data-only formats and integrity checks.",
    ),
    "CWE-523": (
        "Unprotected Transport of Credentials",
        "Credentials are transported without adequate protection.",
        "Confirm that login and credential flows always use TLS and are never available over an unencrypted channel.",
        "Transmit credentials only over TLS and enforce HTTPS everywhere.",
    ),
    "CWE-548": (
        "Exposure of Information Through Directory Listing",
        "A directory listing reveals files that were not intended to be exposed.",
        "Request known directory paths and confirm whether the server returns an index listing their contents.",
        "Disable directory listing and keep sensitive files outside the web root.",
    ),
    "CWE-598": (
        "Use of GET Request Method With Sensitive Query Strings",
        "Sensitive information is placed in the query string of a GET request, where it can reach logs and history.",
        "Review requests for sensitive values (tokens, credentials, identifiers) carried in the URL query string.",
        "Send sensitive values in the request body or headers, never in the URL.",
    ),
    "CWE-601": (
        "URL Redirection to Untrusted Site ('Open Redirect')",
        "The application redirects to a URL taken from input without validating it against trusted destinations.",
        "Set redirect parameters to an external benign host and confirm whether the application forwards the browser off-site.",
        "Allow-list redirect destinations and avoid taking full URLs from input.",
    ),
    "CWE-611": (
        "Improper Restriction of XML External Entity Reference",
        "An XML parser processes external entity references in untrusted XML.",
        "On XML-accepting endpoints, submit a benign document that defines an external entity pointing at an approved callback and confirm whether the parser resolves it.",
        "Disable DTD processing and external entities in every XML parser.",
    ),
    "CWE-614": (
        "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
        "A session cookie is set over HTTPS without the Secure attribute, so it may be sent over HTTP.",
        "Inspect Set-Cookie headers for session cookies and confirm the Secure attribute is present.",
        "Set the Secure attribute on all session and sensitive cookies.",
    ),
    "CWE-639": (
        "Authorization Bypass Through User-Controlled Key",
        "The application uses a user-controlled key to reference an object without verifying ownership.",
        "Using two test accounts, request one account's object identifiers while authenticated as the other and confirm access is refused.",
        "Validate object ownership on the server for every request that references an identifier.",
    ),
    "CWE-643": (
        "Improper Neutralization of Data within XPath Expressions ('XPath Injection')",
        "User input alters the meaning of an XPath query because it is not neutralized.",
        "In XML-backed lookups, submit XPath metacharacters and compare the returned data to a baseline for changes.",
        "Use parameterized XPath or strictly validate and escape input.",
    ),
    "CWE-644": (
        "Improper Neutralization of HTTP Headers for Scripting Syntax",
        "Input reflected into HTTP headers is not neutralized against scripting syntax.",
        "Submit harmless scripting syntax in values that are reflected into response headers and review how they are rendered by clients.",
        "Encode header output and reject control characters.",
    ),
    "CWE-693": (
        "Protection Mechanism Failure",
        "A protection mechanism is missing or ineffective, such as absent security headers.",
        "Review responses for expected protections (CSP, X-Content-Type-Options, security headers) and confirm each is present and effective.",
        "Apply a hardened baseline of security headers and protections, and verify they are enforced.",
    ),
    "CWE-798": (
        "Use of Hard-coded Credentials",
        "The application contains hard-coded credentials.",
        "Review client-side code, configuration and accessible artifacts for embedded credentials or keys.",
        "Remove hard-coded secrets; store them in a managed secret store and rotate them.",
    ),
    "CWE-840": (
        "Business Logic Errors",
        "The application's business rules can be abused to reach unintended outcomes.",
        "Define the expected outcome of a workflow, then exercise it with logically invalid but benign test data and compare the actual outcome.",
        "Enforce business rules on the server at every step of the workflow.",
    ),
    "CWE-862": (
        "Missing Authorization",
        "The application does not perform an authorization check before granting access to a resource or function.",
        "Request protected resources and functions with a low-privilege test account and confirm each enforces an authorization check.",
        "Deny by default and enforce authorization on the server for every resource and function.",
    ),
    "CWE-863": (
        "Incorrect Authorization",
        "The application performs an authorization check but does so incorrectly.",
        "Compare each role's intended access with its actual access across resources and functions, looking for checks that pass when they should fail.",
        "Centralize authorization logic and validate it against the intended role model.",
    ),
    "CWE-918": (
        "Server-Side Request Forgery (SSRF)",
        "The application fetches a URL supplied by input without restricting the destination.",
        "On URL-accepting features, point the parameter at an approved out-of-band callback host and confirm whether the server makes the request; never target internal hosts outside scope.",
        "Allow-list destinations, block internal address ranges, and disable unused URL schemes.",
    ),
    "CWE-942": (
        "Permissive Cross-domain Policy with Untrusted Domains",
        "A cross-domain policy trusts untrusted domains, broadening the attack surface.",
        "Review CORS response headers and legacy cross-domain policy files for wildcard or untrusted origins, especially combined with credentials.",
        "Allow-list exact trusted origins and avoid credentials with broad policies.",
    ),
    "CWE-943": (
        "Improper Neutralization of Special Elements in Data Query Logic",
        "Input alters the logic of a data query (SQL, NoSQL or similar) because special elements are not neutralized.",
        "For each data-driven parameter, submit syntax that would alter the query's logic and compare the response to a baseline without running destructive operations.",
        "Use parameterized queries and safe query-building APIs for the relevant data store.",
    ),
    "CWE-1004": (
        "Sensitive Cookie Without 'HttpOnly' Flag",
        "A sensitive cookie is set without HttpOnly, so client-side scripts can read it.",
        "Inspect Set-Cookie headers for session cookies and confirm the HttpOnly attribute is present.",
        "Set HttpOnly on session and other sensitive cookies.",
    ),
    "CWE-1021": (
        "Improper Restriction of Rendered UI Layers or Frames (Clickjacking)",
        "The application can be framed by other sites, enabling clickjacking.",
        "Review sensitive pages for CSP frame-ancestors or X-Frame-Options and confirm they cannot be embedded in a frame.",
        "Set CSP frame-ancestors and X-Frame-Options on sensitive pages.",
    ),
    "CWE-1104": (
        "Use of Unmaintained Third Party Components",
        "The application relies on third-party components that are no longer maintained or are outdated.",
        "Identify component and library versions from fingerprints and metadata and compare them with current maintained releases and advisories.",
        "Maintain an inventory, keep components updated, and retire unmaintained dependencies.",
    ),
    "CWE-1275": (
        "Sensitive Cookie with Improper SameSite Attribute",
        "A sensitive cookie has a missing or weak SameSite attribute, weakening CSRF protection.",
        "Inspect Set-Cookie headers for session cookies and confirm an appropriate SameSite attribute is set.",
        "Set SameSite (Lax or Strict as appropriate) on session and sensitive cookies.",
    ),
    "CWE-1336": (
        "Improper Neutralization of Special Elements Used in a Template Engine ('Server-Side Template Injection')",
        "Input reaches a server-side template engine and is evaluated as template syntax.",
        "Submit a benign template expression into fields rendered by a template engine and observe whether it is evaluated rather than shown literally.",
        "Never build templates from user input, and sandbox the template engine.",
    ),
    "CWE-1392": (
        "Use of Default Credentials",
        "The application or a component still uses vendor default credentials.",
        "Within the agreed rules, check identified products and admin interfaces for documented default accounts.",
        "Change default credentials at deployment and disable unused default accounts.",
    ),
}
