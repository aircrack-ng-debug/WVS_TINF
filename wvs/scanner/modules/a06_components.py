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

from wvs.scanner.models import Issue, Severity # Import new Issue and Severity
# ResultDict will be defined locally or imported from a common types module if created

__all__ = ["run"]

# Define ResultDict locally
ResultDict = Dict[str, List[Issue]]


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
                    id=f"WVS-A06-{comp.upper()}-001", # Example ID
                    name=f"Unable to determine version of {comp}",
                    description=(
                        f"The scanner found `{comp}` but could not extract a semantic version. "
                        "Manual verification recommended to ensure it's not an outdated or vulnerable version."
                    ),
                    severity=Severity.LOW, # Or Severity.INFO depending on policy
                    remediation=f"Manually verify the version of {comp} in use. If it's outdated or known to be vulnerable, update it to a secure version. Ensure version information is consistently available in asset metadata.",
                    references=["https://owasp.org/www-project-proactive-controls/v4/en/identify_and_inventoried_assets"]
                )
            )
        elif _is_outdated(ver, baseline):
            issues.append(
                Issue(
                    id=f"WVS-A06-{comp.upper()}-002", # Example ID
                    name=f"Outdated component: {comp} {ver}",
                    description=(
                        f"Detected {comp} version {ver} which is older than the secure baseline {baseline}. "
                        f"Outdated components can contain known vulnerabilities."
                    ),
                    severity=Severity.MEDIUM,
                    remediation=f"Upgrade {comp} from version {ver} to the latest stable release (at least {baseline} or newer). Regularly check for and apply updates to all third-party components.",
                    references=[f"https://github.com/{comp}/{comp}/releases"] # Potentially make this more generic or look up official advisory links
                )
            )
    return {
        "module": "A06 – Vulnerable & Outdated Components",
        "issues": [issue.to_dict() for issue in issues],
    }