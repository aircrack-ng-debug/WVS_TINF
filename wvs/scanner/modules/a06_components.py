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