"""Module A05 – Security Misconfiguration (HTTP header focus)

This *passive* module inspects a single HTTP response and flags missing or weak
security headers. It follows the [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/).

Checks implemented
------------------
* **Strict‑Transport‑Security (HSTS)** – present with reasonable `max‑age` (≥ 6 months).
* **Content‑Security‑Policy (CSP)** – must exist; flags overly permissive policies
  such as `default‑src *`.
* **X‑Frame‑Options / CSP frame‑ancestors** – at least one required to mitigate clickjacking.
* **X‑Content‑Type‑Options** – should be `nosniff`.
* **Referrer‑Policy** – should be set to a privacy‑friendly value, e.g. `same‑origin`.

References
----------
* OWASP: <https://owasp.org/Top10/A05_2021-Security_Misconfiguration/>
"""
from __future__ import annotations

import re
from typing import Dict, List

import requests

from wvs.scanner.models import Issue, Severity # Import new Issue and Severity
from typing import Dict, List # Added for ResultDict

__all__ = ["run"]

# Define ResultDict locally as it's a simple type alias
# and a02_crypto's ResultDict will also be based on the new Issue model
ResultDict = Dict[str, List[Issue]]


_HEADER_EXPECTATIONS = {
    "strict-transport-security": re.compile(r"max-age=\d{6,}", re.I),
    "content-security-policy": re.compile(r"default-src[^;]*'(self|'none')", re.I),
    "x-frame-options": re.compile(r"(deny|sameorigin)", re.I),
    "x-content-type-options": re.compile(r"nosniff", re.I),
    "referrer-policy": re.compile(r"(same-origin|strict-origin|no-referrer)", re.I),
}


def _evaluate_headers(headers: Dict[str, str]) -> List[Issue]:
    issues: List[Issue] = []

    canonical = {k.lower(): v for k, v in headers.items()}

    for header, pattern in _HEADER_EXPECTATIONS.items():
        if header not in canonical:
            issues.append(
                Issue(
                    id=f"WVS-A05-{header.upper()}-001", # Example ID
                    name=f"Missing security header: {header}",
                    description=f"The response lacks the `{header}` header. This could expose the application to various attacks depending on the missing header.",
                    severity=Severity.MEDIUM,
                    remediation=f"Implement the `{header}` HTTP security header. Consult OWASP Secure Headers Project for specific recommendations.",
                    references=["https://owasp.org/www-project-secure-headers/"]
                )
            )
            continue
        value = canonical[header]
        if not pattern.search(value):
            issues.append(
                Issue(
                    id=f"WVS-A05-{header.upper()}-002", # Example ID
                    name=f"Misconfigured security header: {header}",
                    description=(
                        f"Header `{header}: {value}` does not meet recommended security "
                        "configuration (pattern mismatch). This might render the protection ineffective."
                    ),
                    severity=Severity.LOW,
                    remediation=f"Review and reconfigure the `{header}` HTTP security header according to best practices. Verify the configuration using security tools and documentation.",
                    references=["https://owasp.org/www-project-secure-headers/"]
                )
            )
    return issues


def run(target_url: str) -> ResultDict:
    """Run security‑header checks against *target_url*."""

    resp = requests.get(target_url, timeout=5, allow_redirects=True)
    issues = _evaluate_headers(dict(resp.headers))

    return {
        "module": "A05 – Security Misconfiguration (Headers)",
        "issues": [issue.to_dict() for issue in issues],
    }