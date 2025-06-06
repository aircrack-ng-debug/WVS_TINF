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