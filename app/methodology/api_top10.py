"""OWASP API Security Top 10 (2023) review checklist, summarized in this platform's own words."""
from __future__ import annotations

from dataclasses import dataclass

FRAMEWORK = "OWASP API Security Top 10"
FRAMEWORK_VERSION = "2023"
CATEGORY = "APITOP10"
CATEGORY_LABEL = "OWASP API Security Top 10"
_EVIDENCE = "Requests and responses for each test account, with credentials and sensitive data redacted."
_VALIDATION = "A tester reproduces the behavior with authorized test accounts and confirms the data or function exposed."


@dataclass(frozen=True)
class ApiCase:
    code: str
    title: str
    severity: str
    objective: str
    procedure: str
    expected: str
    remediation: str
    category: str = CATEGORY
    tools: tuple[str, ...] = ("Burp Suite", "Authorization matrix")
    automation: str = "manual"
    evidence: str = _EVIDENCE
    validation: str = _VALIDATION

    @property
    def test_id(self) -> str:
        return f"OWASP-API{self.code}-2023"

    @property
    def reference(self) -> str:
        return f"API{self.code}:2023"


CASES = (
    ApiCase("1", "Broken object level authorization", "high", "Confirm every object access checks ownership.", "Compare object requests across two test accounts in the authorization matrix.", "Accounts can only reach their own objects.", "Check ownership on every request that uses an object identifier."),
    ApiCase("2", "Broken authentication", "critical", "Review how API clients authenticate.", "Review token issuance, lifetime, validation and recovery flows with test accounts.", "Authentication is strong and tokens are validated on every call.", "Use standard authentication, short-lived tokens and rate-limited login."),
    ApiCase("3", "Broken object property level authorization", "high", "Confirm that each role sees and changes only permitted fields.", "Compare response fields by role, and review which fields each role may update.", "Sensitive properties are neither exposed nor writable.", "Return explicit response schemas and allow-list writable fields."),
    ApiCase("4", "Unrestricted resource consumption", "medium", "Review limits on expensive API use.", "Review documented quotas, page sizes and upload limits with the client. Avoid load testing unless it is agreed.", "Requests, payload sizes and costs are limited.", "Apply rate limits, quotas, pagination caps and timeouts."),
    ApiCase("5", "Broken function level authorization", "high", "Confirm that privileged functions enforce roles.", "Record each role's expected access to administrative routes in the authorization matrix.", "Lower-privilege roles cannot use privileged functions.", "Deny by default and enforce role checks on every function."),
    ApiCase("6", "Unrestricted access to sensitive business flows", "medium", "Identify flows that could be harmed by excessive automated use.", "Review purchase, booking and similar flows, and the controls that limit automated use.", "Sensitive flows have abuse protections.", "Add business-level limits, device checks and monitoring."),
    ApiCase("7", "Server-side request forgery", "high", "Review APIs that fetch user-supplied URLs.", "Identify URL-accepting parameters and review their allow-list design with the client.", "Server-side fetches reach only approved destinations.", "Allow-list destinations and block internal address ranges."),
    ApiCase("8", "Security misconfiguration", "medium", "Review API security configuration.", "Review TLS, CORS, security headers, error messages and enabled methods.", "Configuration follows a hardened baseline.", "Automate hardening and remove unnecessary features."),
    ApiCase("9", "Improper inventory management", "medium", "Confirm every API version and host is known.", "Compare the API inventory with documentation, and look for old or undocumented versions.", "All API hosts and versions are documented and supported.", "Maintain an inventory and retire old versions."),
    ApiCase("10", "Unsafe consumption of APIs", "medium", "Review how the application trusts third-party APIs.", "Review third-party integrations for validation of received data and encrypted transport.", "Third-party data is validated like user input.", "Validate upstream responses and limit redirects and timeouts."),
)
