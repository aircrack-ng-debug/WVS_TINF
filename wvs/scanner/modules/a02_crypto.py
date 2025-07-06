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
from typing import List

import requests

from wvs.scanner.base_module import BaseScannerModule
from wvs.scanner.models import Issue, Severity

# --------------------------------------------------------------------------------------
# TLS helpers
# --------------------------------------------------------------------------------------

_WEAK_CIPHERS_RE = re.compile(
    r"(RC4|DES|3DES|NULL|EXPORT|MD5)", re.IGNORECASE
)  # quick heuristic list


class A02CryptoScanner(BaseScannerModule):
    """
    Scanner module for A02 Cryptographic Failures.
    Checks for weak TLS configurations and insecure cookie flags.
    """
    NAME = "A02 Cryptographic Failures"

    def _check_tls(self, target_url: str) -> List[Issue]:
        """Perform a minimal TLS handshake and derive protocol / cipher properties.

        The socket handshake is wrapped in a short timeout (3 s) so that scanners
        don't hang for unreachable hosts. self.timeout is not used here as
        socket.create_connection has its own timeout parameter which is more
        specific for the connection phase. The 3s timeout is deemed appropriate
        for a handshake.
        """

        parsed = _urlparse.urlparse(target_url)
        host = parsed.hostname or target_url
        port = parsed.port or 443

        ctx = ssl.create_default_context()
        ctx.set_ciphers("ALL:@SECLEVEL=0")  # allow handshake—even with weak suites—for inspection
        issues: List[Issue] = []

        try:
            # Using a fixed timeout of 3s for the handshake itself.
            # self.timeout could be used if a configurable handshake timeout is desired.
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
                        id="WVS-A02-001",
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
                        id="WVS-A02-002",
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
                    id="WVS-A02-003",
                )
            )
        return issues

# --------------------------------------------------------------------------------------
    # Cookie helpers
    # --------------------------------------------------------------------------------------

    def _check_cookies(self, target_url: str) -> List[Issue]:
        """Issue a `GET` request and inspect the `Set‐Cookie` headers."""

        resp = requests.get(target_url, timeout=self.timeout, allow_redirects=True)

        issues: List[Issue] = []
        # The loop `for cookie in resp.cookies.list_domains():` was empty and thus removed.
        # Direct iteration over headers is more reliable as per original comment.

        set_cookie_header_str = resp.headers.get("Set-Cookie")
        if set_cookie_header_str:
            # Split by comma to handle multiple Set-Cookie headers in a single string
            set_cookie_headers = [h.strip() for h in set_cookie_header_str.split(',')]
        else:
            set_cookie_headers = []

        for hdr in set_cookie_headers:
            # Normalise attributes for search
            attr = hdr.lower()
            if "secure" not in attr:
                issues.append(
                    Issue(
                        id="WVS-A02-004",
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
                        id="WVS-A02-005",
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

    def scan(self, target_url: str) -> List[Issue]:
        """Run all A02 cryptographic checks for *target_url* and return a list of issues."""
        issues: List[Issue] = []
        issues.extend(self._check_tls(target_url))
        issues.extend(self._check_cookies(target_url))
        return issues