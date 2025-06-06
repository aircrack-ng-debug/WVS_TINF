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