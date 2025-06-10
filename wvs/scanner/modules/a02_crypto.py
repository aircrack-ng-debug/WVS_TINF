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
from typing import Dict, List

import requests

from wvs.scanner.models import Issue, Severity

__all__ = ["run", "ResultDict"] # Issue is now imported

# --------------------------------------------------------------------------------------
# Dataclasses & Types
# --------------------------------------------------------------------------------------
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
                    severity=Severity.HIGH,
                    remediation="Configure the server to use TLS 1.2 or TLS 1.3. Disable support for older protocols like SSLv3, TLS 1.0, and TLS 1.1.",
                    references=["https://owasp.org/www-project-secure-headers/#strict-transport-security"],
                    id="WVS-A02-001", # Example ID
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
                    severity=Severity.HIGH,
                    remediation="Configure the server to use strong cipher suites. Prioritize AEAD ciphers and those that support Perfect Forward Secrecy. Consult Mozilla's Server Side TLS guidelines for recommended configurations.",
                    references=["https://datatracker.ietf.org/doc/html/rfc7457"],
                    id="WVS-A02-002", # Example ID
                )
            )
    except Exception as exc:
        issues.append(
            Issue(
                name="TLS handshake failed",
                description=f"TLS connection to {host}:{port} failed: {exc}",
                severity=Severity.HIGH,
                remediation="Ensure the target host and port are reachable and that there are no network issues (e.g., firewall rules) blocking the connection. Verify the TLS/SSL certificate is valid and correctly installed.",
                references=["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"],
                id="WVS-A02-003", # Example ID
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

    for hdr in resp.headers.get_all("Set-Cookie"):  # Python 3.11+ get_all()
        # Normalise attributes for search
        attr = hdr.lower()
        if "secure" not in attr:
            issues.append(
                Issue(
                    id="WVS-A02-004", # Example ID
                    name="Cookie without `Secure` flag",
                    description=f"`Set-Cookie` header `{hdr}` lacks the `Secure` attribute. The cookie can be transmitted over unencrypted channels.",
                    severity=Severity.MEDIUM,
                    remediation="Add the `Secure` attribute to all sensitive cookies. This ensures they are only sent over HTTPS.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies"]
                )
            )
        if "httponly" not in attr:
            issues.append(
                Issue(
                    id="WVS-A02-005", # Example ID
                    name="Cookie without `HttpOnly` flag",
                    description=f"`Set-Cookie` header `{hdr}` lacks the `HttpOnly` attribute. The cookie can be accessed by client-side scripts, increasing XSS risk.",
                    severity=Severity.MEDIUM,
                    remediation="Add the `HttpOnly` attribute to all cookies that do not need to be accessed by JavaScript. This mitigates the risk of cookie theft via XSS.",
                    references=["https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure.html"]
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
        "issues": [issue.to_dict() for issue in issues],
    }