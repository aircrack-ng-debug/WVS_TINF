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