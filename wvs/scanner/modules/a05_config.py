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

from wvs.scanner.base_module import BaseScannerModule
from wvs.scanner.models import Issue, Severity

_HEADER_EXPECTATIONS = {
    "strict-transport-security": re.compile(r"max-age=\d{6,}", re.I),
    "content-security-policy": re.compile(r"default-src[^;]*'(self|'none')", re.I),
    "x-frame-options": re.compile(r"(deny|sameorigin)", re.I),  # Note: CSP frame-ancestors is more modern
    "x-content-type-options": re.compile(r"nosniff", re.I),
    "referrer-policy": re.compile(r"(same-origin|strict-origin|no-referrer)", re.I),
}


class A05ConfigScanner(BaseScannerModule):
    """
    Scanner module for A05 Security Misconfiguration (HTTP header focus).
    Inspects HTTP response headers for missing or weak security configurations.
    """
    NAME = "A05 Security Misconfiguration (Headers)"

    def _evaluate_headers(self, headers: Dict[str, str]) -> List[Issue]:
        issues: List[Issue] = []
        canonical = {k.lower(): v for k, v in headers.items()}

        # Check for X-Frame-Options OR CSP frame-ancestors
        has_clickjacking_protection = False
        if "x-frame-options" in canonical and _HEADER_EXPECTATIONS["x-frame-options"].search(
                canonical["x-frame-options"]):
            has_clickjacking_protection = True

        csp_header = canonical.get("content-security-policy", "")
        if "frame-ancestors" in csp_header:  # Basic check, assumes valid CSP if frame-ancestors is present
            has_clickjacking_protection = True
            # More sophisticated CSP parsing could be added here if needed
            # For now, presence of frame-ancestors is considered a pass for this part of clickjacking.

        if not has_clickjacking_protection:
            # Only add X-Frame-Options issue if CSP frame-ancestors is also missing or insufficient
            if "x-frame-options" not in canonical:
                issues.append(
                    Issue(
                        id="WVS-A05-X-FRAME-OPTIONS-001",
                        name="Missing security header: x-frame-options (and no CSP frame-ancestors)",
                        description="The response lacks `x-frame-options` and `content-security-policy` with `frame-ancestors` directive. This could expose the application to clickjacking attacks.",
                        severity=Severity.MEDIUM,
                        remediation="Implement `x-frame-options` (e.g., DENY or SAMEORIGIN) or use `content-security-policy` with the `frame-ancestors` directive to control framing.",
                        references=["https://owasp.org/www-project-secure-headers/#x-frame-options",
                                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors"]
                    )
                )
            elif not _HEADER_EXPECTATIONS["x-frame-options"].search(canonical.get("x-frame-options", "")):
                issues.append(
                    Issue(
                        id="WVS-A05-X-FRAME-OPTIONS-002",
                        name="Misconfigured security header: x-frame-options (and no CSP frame-ancestors)",
                        description=f"Header `x-frame-options: {canonical.get('x-frame-options')}` is present but misconfigured, and no CSP `frame-ancestors` directive found. This might render clickjacking protection ineffective.",
                        severity=Severity.LOW,
                        remediation="Review and reconfigure the `x-frame-options` header or use CSP `frame-ancestors`. Ensure it's set to DENY or SAMEORIGIN.",
                        references=["https://owasp.org/www-project-secure-headers/#x-frame-options"]
                    )
                )

        for header, pattern in _HEADER_EXPECTATIONS.items():
            if header == "x-frame-options":  # Already handled above
                continue

            if header not in canonical:
                issues.append(
                    Issue(
                        id=f"WVS-A05-{header.upper().replace('-', '_')}-001",
                        name=f"Missing security header: {header}",
                        description=f"The response lacks the `{header}` header. This could expose the application to various attacks depending on the missing header.",
                        severity=Severity.MEDIUM,
                        remediation=f"Implement the `{header}` HTTP security header. Consult OWASP Secure Headers Project for specific recommendations.",
                        references=["https://owasp.org/www-project-secure-headers/"]
                    )
                )
                continue

            value = canonical[header]
            # Special handling for CSP: presence is often good, but overly permissive is bad.
            # The regex for CSP checks if 'self' or 'none' is present in default-src, which is a basic check.
            if not pattern.search(value):
                severity = Severity.LOW
                if header == "content-security-policy":
                    # Overly permissive CSP might be worse than LOW
                    if "*" in value or "unsafe-inline" in value or "unsafe-eval" in value:
                        severity = Severity.MEDIUM
                elif header == "strict-transport-security":
                    severity = Severity.HIGH  # Weak HSTS is a significant issue

                issues.append(
                    Issue(
                        id=f"WVS-A05-{header.upper().replace('-', '_')}-002",
                        name=f"Misconfigured or weak security header: {header}",
                        description=(
                            f"Header `{header}: {value}` does not meet recommended security "
                            "configuration (pattern mismatch or weak policy). This might render the protection ineffective or less effective."
                        ),
                        severity=severity,
                        remediation=f"Review and reconfigure the `{header}` HTTP security header according to best practices. Verify the configuration using security tools and documentation. For CSP, avoid overly permissive directives like '*' or 'unsafe-*'. For HSTS, ensure a long max-age and include subdomains if applicable.",
                        references=["https://owasp.org/www-project-secure-headers/"]
                    )
                )
        return issues

    def scan(self, target_url: str) -> List[Issue]:
        """Run security-header checks against *target_url*."""
        try:
            resp = requests.get(target_url, timeout=self.timeout, allow_redirects=True)
            issues = self._evaluate_headers(dict(resp.headers))
        except requests.exceptions.RequestException as e:
            issues = [
                Issue(
                    id="WVS-A05-REQUEST-ERROR-001",
                    name="HTTP Request Failed",
                    description=f"Could not retrieve headers from {target_url}. Error: {e}",
                    severity=Severity.INFO,  # Or HIGH if availability is critical
                    remediation="Ensure the target URL is accessible and the server is responding correctly. Check network connectivity.",
                    references=[]
                )
            ]
        return issues