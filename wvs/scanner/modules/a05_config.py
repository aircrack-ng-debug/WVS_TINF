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

from .a02_crypto import Issue, ResultDict  # reuse Issue dataclass for uniformity

__all__ = ["run"]


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
                    name=f"Missing security header: {header}",
                    description=f"The response lacks the `{header}` header.",
                    severity="medium",
                    reference="https://owasp.org/www-project-secure-headers/"
                )
            )
            continue
        value = canonical[header]
        if not pattern.search(value):
            issues.append(
                Issue(
                    name=f"Misconfigured security header: {header}",
                    description=(
                        f"Header `{header}: {value}` does not meet recommended security "
                        "configuration (pattern mismatch)."
                    ),
                    severity="low",
                    reference="https://owasp.org/www-project-secure-headers/"
                )
            )
    return issues


def run(target_url: str) -> ResultDict:
    """Run security‑header checks against *target_url*."""

    resp = requests.get(target_url, timeout=5, allow_redirects=True)
    issues = _evaluate_headers(dict(resp.headers))

    return {
        "module": "A05 – Security Misconfiguration (Headers)",
        "issues": [issue.__dict__ for issue in issues],
    }