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

from wvs.scanner.base_module import BaseScannerModule
from wvs.scanner.models import Issue, Severity

# --- baseline versions ----------------------------------------------------------------
_BASELINES: Dict[str, str] = {
    "jquery": "3.6.0",
    "bootstrap": "4.6.0",  # Example: baseline for Bootstrap 4.x. For 5.x, it would be higher.
    "angular": "1.8.0",  # angularJS (legacy)
    # Add more components and their secure baselines here
    # e.g., "react": "17.0.2", "vue": "2.6.14" (or "3.2.30" for Vue 3)
}

_SEMVER_RE = re.compile(r"(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)")


# --- scanner class --------------------------------------------------------------------------

class A06ComponentsScanner(BaseScannerModule):
    """
    Scanner module for A06 Vulnerable and Outdated Components.
    Performs passive scraping to infer front-end framework versions and flags those
    below a hard-coded secure baseline.
    """
    NAME = "A06 Vulnerable & Outdated Components"

    def _parse_version(self, text: str) -> Optional[str]:
        m = _SEMVER_RE.search(text)
        return m.group(0) if m else None

    def _is_outdated(self, ver: str, baseline: str) -> bool:
        try:
            ver_tuple: Tuple[int, ...] = tuple(map(int, ver.split(".")))
            base_tuple: Tuple[int, ...] = tuple(map(int, baseline.split(".")))
            # Compare major, then minor, then patch
            return ver_tuple < base_tuple
        except ValueError:  # Handle non-numeric parts if any, though semver should be numeric
            return True  # Treat as outdated if version format is unexpected

    def _scan_html(self, html: str) -> List[Tuple[str, str]]:
        """Return list of (component, version) tuples discovered in *html*."""
        soup = BeautifulSoup(html, "html.parser")
        findings: List[Tuple[str, str]] = []

        # Common places to find version info: <script src>, <link href>, meta generator
        # Script/Link tags for JS/CSS libraries
        for tag in soup.find_all(["script", "link"]):
            attr = tag.get("src") or tag.get("href") or ""
            for comp_name in _BASELINES.keys():
                # Regex to find component name followed by a version-like pattern
                # e.g., jquery-3.5.1.min.js or bootstrap/4.6.0/css/bootstrap.min.css
                match = re.search(rf"{comp_name}[-/](?P<version>\d+\.\d+(\.\d+)?([a-zA-Z0-9.-]*)?)", attr, re.I)
                if match:
                    ver = self._parse_version(match.group("version")) or "unknown"
                    findings.append((comp_name, ver))
                elif comp_name in attr.lower():  # Fallback if specific version pattern fails
                    ver = self._parse_version(attr) or "unknown"
                    findings.append((comp_name, ver))

        # Meta generator tag (e.g., <meta name="generator" content="WordPress 5.8.1">)
        for tag in soup.find_all("meta", attrs={"name": "generator"}):
            content = tag.get("content", "").lower()
            for comp_name in _BASELINES.keys():
                if comp_name in content:
                    ver = self._parse_version(content) or "unknown"
                    findings.append((comp_name, ver))

        # Deduplicate findings, preferring more specific versions if multiple found for same component
        # For now, simple list is returned. Deduplication can be added if needed.
        return list(set(findings))  # Basic deduplication

    def scan(self, target_url: str) -> List[Issue]:
        """Scrape *target_url* and detect outdated JavaScript/CSS components."""
        issues: List[Issue] = []
        try:
            resp = requests.get(target_url, timeout=self.timeout, allow_redirects=True)
            resp.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        except requests.exceptions.RequestException as e:
            issues.append(
                Issue(
                    id="WVS-A06-REQUEST-ERROR-001",
                    name="HTTP Request Failed for Component Scan",
                    description=f"Could not retrieve content from {target_url} to scan for components. Error: {e}",
                    severity=Severity.INFO,
                    remediation="Ensure the target URL is accessible and the server is responding correctly. Check network connectivity.",
                    references=[]
                )
            )
            return issues

        findings = self._scan_html(resp.text)

        for comp, ver in findings:
            baseline = _BASELINES.get(comp)  # Use .get for safety, though keys should exist
            if not baseline:  # Should not happen if _scan_html uses _BASELINES.keys()
                continue

            if ver == "unknown":
                issues.append(
                    Issue(
                        id=f"WVS-A06-{comp.upper().replace('-', '_')}-001",
                        name=f"Unable to determine version of {comp}",
                        description=(
                            f"The scanner found an indication of `{comp}` but could not extract a semantic version string. "
                            "Manual verification is recommended to ensure it's not an outdated or vulnerable version."
                        ),
                        severity=Severity.LOW,
                        remediation=f"Manually verify the version of {comp} in use. If it's outdated or known to be vulnerable, update it to a secure version. Ensure version information is consistently available in asset metadata or filenames.",
                        references=["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"]
                    )
                )
            elif self._is_outdated(ver, baseline):
                issues.append(
                    Issue(
                        id=f"WVS-A06-{comp.upper().replace('-', '_')}-002",
                        name=f"Outdated component: {comp} {ver}",
                        description=(
                            f"Detected {comp} version {ver}, which is older than the recommended secure baseline of {baseline}. "
                            f"Outdated components can contain known vulnerabilities that could be exploited."
                        ),
                        severity=Severity.MEDIUM,  # Could be HIGH if component is critical & widely exploited
                        remediation=f"Upgrade {comp} from version {ver} to the latest stable release (at least {baseline} or newer). Regularly check for and apply updates to all third-party components. Consider using Software Composition Analysis (SCA) tools.",
                        references=[
                            "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
                            # Specific advisory links are hard to generate dynamically here,
                            # but users should search for advisories for "comp version".
                            # Example: f"https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query={comp}+{ver}&search_type=all"
                        ]
                    )
                )
        return issues