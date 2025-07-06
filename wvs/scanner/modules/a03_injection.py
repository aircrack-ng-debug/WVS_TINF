
import requests
from typing import List, Set
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup, Tag
from wvs.scanner.base_module import BaseScannerModule
from wvs.scanner.models import Issue, Severity

class A03InjectionScanner(BaseScannerModule):
    """
    Scanner module for detecting A03:2021-Injection vulnerabilities,
    focusing on Reflected Cross-Site Scripting (XSS) and Error-Based SQL Injection (SQLi).
    """
    NAME = "A03 Injection Scanner"

    def __init__(self, timeout: int = 10):
        super().__init__(timeout)
        self.xss_payload = "<script>alert('WVS-XSS-Test')</script>"
        self.sqli_payloads = ["'", "\'\"", "' OR 1=1--"]
        self.sqli_error_patterns = [
            "you have an error in your sql syntax",
            "unclosed quotation mark",
            "supplied argument is not a valid mysql",
            "warning: mysql_fetch_array()",
            "ora-01756",
            "invalid sql statement",
            "odbc driver error",
            "microsoft ole db provider for odbc drivers error",
            "microsoft jet database engine error",
            "sqlite3.operationalerror",
        ]
        self.visited_urls: Set[str] = set()

    def _get_all_forms(self, soup: BeautifulSoup) -> List[Tag]:
        """Extracts all forms from a BeautifulSoup object."""
        return soup.find_all("form")

    def _get_all_links(self, soup: BeautifulSoup) -> List[str]:
        """Extracts all links from a BeautifulSoup object."""
        links = []
        for link in soup.find_all("a", href=True):
            links.append(link["href"])
        return links

    def _test_reflected_xss(self, url: str, method: str, params: dict) -> bool:
        """
        Tests a single URL with a given parameter set for reflected XSS.
        Returns True if the payload is found reflected in the response.
        """
        try:
            if method.upper() == "POST":
                response = requests.post(url, data=params, timeout=self.timeout, verify=False)
            else:
                response = requests.get(url, params=params, timeout=self.timeout, verify=False)

            # Check if the payload is reflected in the response body
            if self.xss_payload in response.text:
                return True
        except requests.RequestException:
            # Ignore connection errors, timeouts, etc.
            pass
        return False

    def _test_error_based_sqli(self, url: str, method: str, params: dict) -> bool:
        """
        Tests a single URL with a given parameter set for error-based SQLi.
        Returns True if a known SQL error pattern is found in the response.
        """
        try:
            if method.upper() == "POST":
                response = requests.post(url, data=params, timeout=self.timeout, verify=False)
            else:
                response = requests.get(url, params=params, timeout=self.timeout, verify=False)

            # Check for common SQL error messages in the response body
            for error in self.sqli_error_patterns:
                if error in response.text.lower():
                    return True
        except requests.RequestException:
            pass
        return False

    def scan(self, target_url: str) -> List[Issue]:
        """
        Performs the scan for injection vulnerabilities.
        """
        if target_url in self.visited_urls:
            return []

        self.visited_urls.add(target_url)
        issues: List[Issue] = []
        print(f"  [A03] Analyzing {target_url} for forms and links...")

        try:
            response = requests.get(target_url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.content, "html.parser")
        except requests.RequestException as e:
            print(f"  [A03] Could not fetch {target_url}: {e}")
            return issues

        # --- Test Forms ---
        forms = self._get_all_forms(soup)
        for form in forms:
            action = form.get("action", "")
            form_url = urljoin(target_url, action)
            method = form.get("method", "get").upper()
            inputs = form.find_all(["input", "textarea", "select"])
            
            # Test for XSS
            for xss_test_input in inputs:
                input_name = xss_test_input.get("name")
                if not input_name:
                    continue
                
                data = {i.get("name"): "test" for i in inputs if i.get("name")}
                data[input_name] = self.xss_payload

                if self._test_reflected_xss(form_url, method, data):
                    issue = Issue(
                        id="WVS-A03-001",
                        name="Reflected Cross-Site Scripting (XSS)",
                        description=f"A potential reflected XSS vulnerability was found in a form at '{form_url}'. The payload was injected into the '{input_name}' parameter.",
                        severity=Severity.MEDIUM,
                        remediation="Implement context-aware output encoding on all user-supplied data. Use a library like OWASP ESAPI.",
                        references=["https://owasp.org/www-community/attacks/xss/"],
                    )
                    issues.append(issue)
                    break # One issue per form is enough

            # Test for SQLi
            for sqli_test_input in inputs:
                input_name = sqli_test_input.get("name")
                if not input_name:
                    continue

                for payload in self.sqli_payloads:
                    data = {i.get("name"): "test" for i in inputs if i.get("name")}
                    data[input_name] = payload
                    
                    if self._test_error_based_sqli(form_url, method, data):
                        issue = Issue(
                            id="WVS-A03-002",
                            name="Error-Based SQL Injection",
                            description=f"A potential error-based SQLi vulnerability was found in a form at '{form_url}'. An SQL error was triggered by injecting a payload into the '{input_name}' parameter.",
                            severity=Severity.HIGH,
                            remediation="Use parameterized queries (prepared statements) to prevent user input from being interpreted as SQL commands.",
                            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                        )
                        issues.append(issue)
                        break # Move to next form after finding one SQLi
                if any(i.id == "WVS-A03-002" for i in issues):
                    break

        # --- Test Links (GET parameters) ---
        links = self._get_all_links(soup)
        for link in links:
            link_url = urljoin(target_url, link)
            parsed_link = urlparse(link_url)
            
            # Only test links within the same domain
            if parsed_link.netloc != urlparse(target_url).netloc:
                continue

            params = parsed_link.query.split('&')
            for i, param in enumerate(params):
                if '=' not in param:
                    continue
                
                param_name = param.split('=')[0]
                
                # Test for XSS
                test_params_xss = list(params)
                test_params_xss[i] = f"{param_name}={self.xss_payload}"
                test_url_xss = parsed_link._replace(query="&".join(test_params_xss)).geturl()
                
                if self._test_reflected_xss(test_url_xss, "GET", {}):
                    issue = Issue(
                        id="WVS-A03-001",
                        name="Reflected Cross-Site Scripting (XSS)",
                        description=f"A potential reflected XSS vulnerability was found in a GET parameter at '{link_url}'. The payload was injected into the '{param_name}' parameter.",
                        severity=Severity.MEDIUM,
                        remediation="Implement context-aware output encoding on all user-supplied data. Use a library like OWASP ESAPI.",
                        references=["https://owasp.org/www-community/attacks/xss/"],
                    )
                    if not any(i.id == issue.id and i.description == issue.description for i in issues):
                        issues.append(issue)

                # Test for SQLi
                for payload in self.sqli_payloads:
                    test_params_sqli = list(params)
                    test_params_sqli[i] = f"{param_name}={payload}"
                    test_url_sqli = parsed_link._replace(query="&".join(test_params_sqli)).geturl()

                    if self._test_error_based_sqli(test_url_sqli, "GET", {}):
                        issue = Issue(
                            id="WVS-A03-002",
                            name="Error-Based SQL Injection",
                            description=f"A potential error-based SQLi vulnerability was found in a GET parameter at '{link_url}'. An SQL error was triggered by injecting a payload into the '{param_name}' parameter.",
                            severity=Severity.HIGH,
                            remediation="Use parameterized queries (prepared statements) to prevent user input from being interpreted as SQL commands.",
                            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                        )
                        if not any(i.id == issue.id and i.description == issue.description for i in issues):
                            issues.append(issue)
                        break # Next parameter

        return issues
