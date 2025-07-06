
import unittest
from unittest.mock import patch, MagicMock
from bs4 import BeautifulSoup
from wvs.scanner.modules.a03_injection import A03InjectionScanner
from wvs.scanner.models import Issue, Severity

class TestA03InjectionScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = A03InjectionScanner(timeout=1)

    def _mock_response(self, text="", status_code=200, headers=None):
        """Helper to create a mock response object."""
        mock = MagicMock()
        mock.text = text
        mock.content = text.encode('utf-8')
        mock.status_code = status_code
        mock.headers = headers or {'Content-Type': 'text/html'}
        return mock

    @patch('requests.get')
    def test_scan_no_vulnerabilities(self, mock_get):
        """Test scanning a page with no forms or links that are vulnerable."""
        html_content = '''
        <html>
            <body>
                <p>This is a safe page.</p>
                <a href="/safe_page">Safe Link</a>
            </body>
        </html>
        '''
        mock_get.return_value = self._mock_response(text=html_content)
        
        issues = self.scanner.scan("http://test.com")
        
        self.assertEqual(len(issues), 0)

    @patch('requests.post')
    @patch('requests.get')
    def test_scan_finds_reflected_xss_in_form(self, mock_get, mock_post):
        """Test finding a reflected XSS vulnerability in a POST form."""
        form_html = '''
        <html>
            <body>
                <form action="/search" method="post">
                    <input type="text" name="query">
                    <input type="submit">
                </form>
            </body>
        </html>
        '''
        # Initial GET to find the form
        mock_get.return_value = self._mock_response(text=form_html)
        
        # POST response that reflects the payload
        xss_payload = "<script>alert('WVS-XSS-Test')</script>"
        reflected_html = f"<html><body>Search results for: {xss_payload}</body></html>"
        mock_post.return_value = self._mock_response(text=reflected_html)

        issues = self.scanner.scan("http://test.com")

        self.assertEqual(len(issues), 1)
        issue = issues[0]
        self.assertEqual(issue.id, "WVS-A03-001")
        self.assertEqual(issue.severity, Severity.MEDIUM)
        self.assertIn("'query' parameter", issue.description)

    @patch('requests.get')
    def test_scan_finds_error_based_sqli_in_get_parameter(self, mock_get):
        """Test finding an error-based SQLi vulnerability in a GET parameter."""
        link_html = '''
        <html>
            <body>
                <a href="/products?id=1">Product 1</a>
            </body>
        </html>
        '''
        # 1. Initial GET to find the link
        # 2. GET for the XSS test (which should be safe)
        # 3. GET for the SQLi test (which should trigger the error)
        mock_get.side_effect = [
            self._mock_response(text=link_html),
            self._mock_response(text="safe response"),
            self._mock_response(text="you have an error in your sql syntax"),
        ]

        issues = self.scanner.scan("http://test.com")

        # Should find one SQLi issue
        self.assertEqual(len(issues), 1)
        issue = issues[0]
        self.assertEqual(issue.id, "WVS-A03-002")
        self.assertEqual(issue.severity, Severity.HIGH)
        self.assertIn("'id' parameter", issue.description)

    @patch('requests.get')
    def test_scan_avoids_external_links(self, mock_get):
        """Test that the scanner does not follow and test external links."""
        html_content = '''
        <html>
            <body>
                <a href="http://external.com/page">External Link</a>
            </body>
        </html>
        '''
        mock_get.return_value = self._mock_response(text=html_content)

        issues = self.scanner.scan("http://test.com")

        self.assertEqual(len(issues), 0)
        # The mock_get should only be called once for the initial page scan
        self.assertEqual(mock_get.call_count, 1)

if __name__ == '__main__':
    unittest.main()
