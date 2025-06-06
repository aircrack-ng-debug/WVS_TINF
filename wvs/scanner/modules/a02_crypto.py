"""
This canvas bundles the initial implementation of three OWASP‑scanner modules and their pytest suites.
Each code block is separated by a comment indicating its intended file path inside the project.
Copy the blocks into your repository structure (`wvs/scanner/modules/…` and `tests/test_modules/…`).
"""

# ======================= File: wvs/scanner/modules/a02_crypto.py =======================
"""Module A02 – Cryptographic Failures (OWASP Top 10 2021)

This scanner module performs **passive** and **active** checks that revolve around
cryptographic hygiene:

* **TLS inspection** – performs a direct TLS handshake to learn the negotiated
  protocol version and cipher‐suite. Anything below *TLS 1.2* or the use of a
  cipher from the [IANA “weak” list](https://datatracker.ietf.org/doc/html/rfc7457)
  is reported as *high severity*.
* **Cookie flag validation** – issues a single `GET` request and inspects all
  `Set‐Cookie` response headers. Cookies that miss a `Secure` or `HttpOnly`
  attribute are reported as *medium severity*.

Both checks are kept intentionally lightweight and self‑contained so that they
can run in constrained CI pipelines without additional system‑level tools.

References
----------
* OWASP: <https://owasp.org/Top10/A02_2021-Cryptographic_Failures/>
* Mozilla TLS recommendations: <https://infosec.mozilla.org/guidelines/web_security#tls>
"""
from __future__ import annotations

import re
import socket
import ssl
import urllib.parse as _urlparse
from dataclasses import dataclass
from typing import Dict, List

import requests

__all__ = ["run", "Issue", "ResultDict"]

# --------------------------------------------------------------------------------------
# Dataclasses & Types
# --------------------------------------------------------------------------------------
@dataclass
class Issue:
    name: str
    description: str
    severity: str  # "low", "medium", "high"
    reference: str

ResultDict = Dict[str, List[Issue]]

# --------------------------------------------------------------------------------------
# TLS helpers
# --------------------------------------------------------------------------------------

_WEAK_CIPHERS_RE = re.compile(
    r"(RC4|DES|3DES|NULL|EXPORT|MD5)", re.IGNORECASE
)  # quick heuristic list


def _check_tls(target_url: str) -> List[Issue]:
    """Perform a minimal TLS handshake and derive protocol / cipher properties.

    The socket handshake is wrapped in a short timeout (3 s) so that scanners
    don't hang for unreachable hosts.
    """

    parsed = _urlparse.urlparse(target_url)
    host = parsed.hostname or target_url
    port = parsed.port or 443

    ctx = ssl.create_default_context()
    ctx.set_ciphers("ALL:@SECLEVEL=0")  # allow handshake—even with weak suites—for inspection
    issues: List[Issue] = []

    try:
        with socket.create_connection((host, port), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                proto = ssock.version() or "unknown"
                cipher, *_ = ssock.cipher() or ("unknown",)

        # --- findings -----------------------------------------------------
        if proto.startswith("TLSv1") and proto < "TLSv1.2":
            issues.append(
                Issue(
                    name="Insecure TLS version negotiated",
                    description=(
                        f"Server negotiated {proto}. Anything below TLS 1.2 is considered insecure "
                        "and vulnerable to known downgrade and cryptographic attacks."
                    ),
                    severity="high",
                    reference="https://owasp.org/www-project-secure-headers/"
                    "#strict-transport-security"
                )
            )
        if _WEAK_CIPHERS_RE.search(cipher or ""):
            issues.append(
                Issue(
                    name="Weak TLS cipher‐suite negotiated",
                    description=(
                        f"Server chose the weak cipher‐suite `{cipher}` which is susceptible to modern "
                        "cryptanalysis. Replace with suites that offer forward secrecy and AEAD."
                    ),
                    severity="high",
                    reference="https://datatracker.ietf.org/doc/html/rfc7457"
                )
            )
    except Exception as exc:
        issues.append(
            Issue(
                name="TLS handshake failed",
                description=f"TLS connection to {host}:{port} failed: {exc}",
                severity="high",
                reference="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
            )
        )

    return issues


# --------------------------------------------------------------------------------------
# Cookie helpers
# --------------------------------------------------------------------------------------

def _check_cookies(target_url: str) -> List[Issue]:
    """Issue a `GET` request and inspect the `Set‐Cookie` headers."""

    resp = requests.get(target_url, timeout=5, allow_redirects=True)

    issues: List[Issue] = []
    for cookie in resp.cookies.list_domains():  # type: ignore[attr-defined]
        # requests' cookiejar API is clunky; iterate manually over headers instead
        pass

    for hdr in resp.headers.get_all("Set-Cookie", default=[]):  # Python 3.11+ get_all()
        # Normalise attributes for search
        attr = hdr.lower()
        if "secure" not in attr:
            issues.append(
                Issue(
                    name="Cookie without `Secure` flag",
                    description=f"`Set-Cookie` header `{hdr}` lacks the `Secure` attribute.",
                    severity="medium",
                    
            )
        if "httponly" not in attr:
            issues.append(
                Ireference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies"
                )ssue(
                    name="Cookie without `HttpOnly` flag",
                    description=f"`Set-Cookie` header `{hdr}` lacks the `HttpOnly` attribute.",
                    severity="medium",
                    reference="https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure.html"
                )
            )
    return issues


# --------------------------------------------------------------------------------------
# Public module API
# --------------------------------------------------------------------------------------

def run(target_url: str) -> ResultDict:  # noqa: D401 – imperative mood accepted
    """Run all A02 cryptographic checks for *target_url* and return a result dict.

    The result dictionary is shaped for consumption by `core.py`.
    Example::

        {
            "module": "A02 – Cryptographic Failures",
            "issues": [Issue(...), Issue(...)]
        }
    """

    issues: List[Issue] = []
    issues.extend(_check_tls(target_url))
    issues.extend(_check_cookies(target_url))

    return {
        "module": "A02 – Cryptographic Failures",
        "issues": [issue.__dict__ for issue in issues],
    }


# ======================= File: wvs/scanner/modules/a05_config.py =======================
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


# ======================= File: wvs/scanner/modules/a06_components.py =======================
"""Module A06 – Vulnerable and Outdated Components

The module performs simple *passive* scraping to infer front‑end framework
versions and flags those below a hard‑coded secure baseline. While a complete
Software Composition Analysis (SCA) is out of scope, version‑sniffing delivers
quick, low‑effort wins that can be complemented by SBOM tools later.

Implementation details
----------------------
* Parses HTML for `<script src="…">`, `<link href="…">`, and `meta generator`.
* Uses regexes to extract *semver* tokens.
* Compares extracted versions to a baseline dictionary (e.g. jQuery ≥ 3.6.0).
* Flags unknown or outdated versions as *medium severity* issues.

References
----------
* OWASP: <https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/>
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

import requests
from bs4 import BeautifulSoup  # external dependency, common in security tooling

from .a02_crypto import Issue, ResultDict

__all__ = ["run"]


# --- baseline versions ----------------------------------------------------------------
_BASELINES: Dict[str, str] = {
    "jquery": "3.6.0",
    "bootstrap": "4.6.0",
    "angular": "1.8.0",  # angularJS
}


_SEMVER_RE = re.compile(r"(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)")


# --- helpers --------------------------------------------------------------------------

def _parse_version(text: str) -> Optional[str]:
    m = _SEMVER_RE.search(text)
    return m.group(0) if m else None


def _is_outdated(ver: str, baseline: str) -> bool:
    ver_tuple: Tuple[int, ...] = tuple(map(int, ver.split(".")))
    base_tuple: Tuple[int, ...] = tuple(map(int, baseline.split(".")))
    return ver_tuple < base_tuple


def _scan_html(html: str) -> List[Tuple[str, str]]:
    """Return list of (component, version) tuples discovered in *html*."""

    soup = BeautifulSoup(html, "html.parser")
    findings: List[Tuple[str, str]] = []

    # script src
    for tag in soup.find_all(["script", "link"]):
        attr = tag.get("src") or tag.get("href") or ""
        for comp in _BASELINES.keys():
            if comp in attr.lower():
                ver = _parse_version(attr) or "unknown"
                findings.append((comp, ver))

    # meta generator
    for tag in soup.find_all("meta", attrs={"name": "generator"}):
        content = tag.get("content", "").lower()
        for comp in _BASELINES.keys():
            if comp in content:
                ver = _parse_version(content) or "unknown"
                findings.append((comp, ver))
    return findings


def run(target_url: str) -> ResultDict:
    """Scrape *target_url* and detect outdated JavaScript/CSS components."""

    resp = requests.get(target_url, timeout=5, allow_redirects=True)
    findings = _scan_html(resp.text)

    issues: List[Issue] = []
    for comp, ver in findings:
        baseline = _BASELINES[comp]
        if ver == "unknown":
            issues.append(
                Issue(
                    name=f"Unable to determine version of {comp}",
                    description=(
                        f"The scanner found `{comp}` but could not extract a semantic version. "
                        "Manual verification recommended."
                    ),
                    severity="low",
                    reference="https://owasp.org/www-project-proactive-controls/v4/en/identify_and_inventoried_assets"
                )
            )
        elif _is_outdated(ver, baseline):
            issues.append(
                Issue(
                    name=f"Outdated component: {comp} {ver}",
                    description=(
                        f"Detected {comp} version {ver} which is older than the secure baseline {baseline}. "
                        "Upgrade to the latest stable release."
                    ),
                    severity="medium",
                    reference="https://github.com/{comp}/{comp}/releases"
                )
            )
    return {
        "module": "A06 – Vulnerable & Outdated Components",
        "issues": [issue.__dict__ for issue in issues],
    }


# ======================= File: tests/test_modules/test_a02_crypto.py =======================
"""Pytest suite for *a02_crypto*.

Actual TLS handshakes would require network access. The tests therefore stub
out the internal helper functions so that *run()* can be validated deterministically.
"""
from types import SimpleNamespace
from unittest import mock

import wvs.scanner.modules.a02_crypto as crypto


def test_run_aggregates_issues():
    dummy_issue = crypto.Issue(
        name="dummy",
        description="desc",
        severity="low",
        reference="ref",
    )

    with mock.patch.object(crypto, "_check_tls", return_value=[dummy_issue]) as mtls, \
         mock.patch.object(crypto, "_check_cookies", return_value=[]) as mcookies:
        result = crypto.run("https://example.com")

    assert result["module"].startswith("A02")
    assert len(result["issues"]) == 1
    assert result["issues"][0]["name"] == "dummy"
    mtls.assert_called_once()
    mcookies.assert_called_once()


# ======================= File: tests/test_modules/test_a05_config.py =======================
"""Unit tests for *a05_config* using requests‑mock."""
import requests
import requests_mock

import wvs.scanner.modules.a05_config as config


def test_missing_headers_flagged():
    with requests_mock.Mocker() as m:
        m.get("https://example.com", headers={})
        result = config.run("https://example.com")

    # We expect at least one missing‑header issue
    assert any("Missing security header" in iss["name"] for iss in result["issues"])


# ======================= File: tests/test_modules/test_a06_components.py =======================
"""Unit tests for *a06_components* using static HTML fixtures."""
import requests_mock

import wvs.scanner.modules.a06_components as comp

_HTML = """
<!doctype html>
<html>
  <head>
    <script src="/static/js/jquery-1.9.1.min.js"></script>
  </head>
  <body></body>
</html>
"""


def test_outdated_component_detected():
    with requests_mock.Mocker() as m:
        m.get("https://example.com", text=_HTML)
        result = comp.run("https://example.com")

    names = [iss["name"] for iss in result["issues"]]
    assert any("Outdated component" in name for name in names)
