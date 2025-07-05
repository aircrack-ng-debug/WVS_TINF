from __future__ import annotations

import urllib.parse
from typing import List

import requests

from wvs.scanner.base_module import BaseScannerModule
from wvs.scanner.models import Issue, Severity


class A01AccessScanner(BaseScannerModule):
    """
    Scanner module for A01 - Broken Access Control.
    Checks for common publicly accessible sensitive files.
    """
    NAME = "A01 Broken Access Control (Sensitive Files)"

    # Common sensitive paths that should ideally not be publicly accessible
    SENSITIVE_PATHS = [
        ".git/config",
        ".env",
        "docker-compose.yml",
        "backup.sql",
        "/.well-known/security.txt",  # While security.txt is good, finding it can be informative
        ".aws/credentials",
        "wp-config.php.bak",  # Example for specific CMS
        "config/database.yml",  # Example for Rails
        "app/config/parameters.yml",  # Example for Symfony
        "WEB-INF/web.xml",  # Example for Java EE
        "backup.zip",
        "database.sql",
        "users.sql",
        "dump.sql",
        "data.sql",
    ]

    def scan(self, target_url: str) -> List[Issue]:
        """
        Scans the target for publicly accessible sensitive files.

        Args:
            target_url: The base URL to scan.

        Returns:
            A list of Issue objects for any found sensitive files.
        """
        issues: List[Issue] = []
        parsed_base_url = urllib.parse.urlparse(target_url)

        for path in self.SENSITIVE_PATHS:
            # Ensure we handle both root-relative and non-root-relative paths correctly
            if path.startswith('/'):
                # Path is absolute, join with scheme and netloc
                full_url = urllib.parse.urljoin(f"{parsed_base_url.scheme}://{parsed_base_url.netloc}", path)
            else:
                # Path is relative, join with the full base_url (including its path if any)
                full_url = urllib.parse.urljoin(target_url if target_url.endswith('/') else target_url + '/', path)

            print(f"[A01AccessScanner] Checking URL: {full_url}")  # For debugging

            try:
                response = requests.get(full_url, timeout=self.timeout, allow_redirects=True,
                                        verify=True)  # Added verify=True

                # Check for 200 OK and also for common directory listing content types if it's a directory-like path
                if response.status_code == 200:
                    # Basic check for directory listing (can be expanded)
                    content_type = response.headers.get("Content-Type", "").lower()
                    is_directory_listing = "text/html" in content_type and any(
                        kw in response.text.lower() for kw in ["index of /", "parent directory"])

                    if is_directory_listing:
                        issue = Issue(
                            id=f"WVS-A01-DIR-{path.replace('/', '-').replace('.', '')}",
                            name=f"Potential Directory Listing Enabled",
                            description=f"The path {path} at {full_url} appears to have directory listing enabled, "
                                        f"which might expose sensitive file structures or unintended files.",
                            severity=Severity.MEDIUM,  # Directory listing is usually medium
                            remediation="Disable directory listing on the web server for this path. "
                                        "Ensure that if a default file (like index.html) is not present, "
                                        "the server does not list the directory contents.",
                            references=["https://owasp.org/www-community/attacks/Directory_Listing"]
                        )
                        issues.append(issue)
                    else:
                        # If not a directory listing, then it's a file found
                        issue = Issue(
                            id=f"WVS-A01-FILE-{path.replace('/', '-').replace('.', '')}",
                            name=f"Publicly Accessible Sensitive File",
                            description=f"A potentially sensitive file was found at: {full_url}. "
                                        f"The file '{path}' should typically not be publicly accessible.",
                            severity=Severity.HIGH,
                            remediation=f"Restrict access to the file '{path}' at {full_url}. "
                                        "Ensure that sensitive files are not deployed to web-accessible directories "
                                        "or are protected by appropriate access controls.",
                            references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"]
                        )
                        issues.append(issue)
                elif response.status_code == 403 and path == "/.well-known/security.txt":
                    # security.txt being forbidden is not an issue, but finding it (even if 403) is a good sign
                    issue = Issue(
                        id="WVS-A01-INFO-SECURITY-TXT-FORBIDDEN",
                        name="Security.txt Found (Access Forbidden)",
                        description=f"A security.txt file was found at: {full_url} but access is forbidden (403). "
                                    "This is generally acceptable, but confirms the file's presence.",
                        severity=Severity.INFO,
                        remediation="Ensure the security.txt file provides accurate contact information for security researchers. "
                                    "A 403 status is acceptable if you don't want it to be fully public, but ensure it's not a misconfiguration.",
                        references=["https://securitytxt.org/"]
                    )
                    issues.append(issue)


            except requests.exceptions.Timeout:
                print(f"[A01AccessScanner] Timeout when checking URL: {full_url}")
            except requests.exceptions.RequestException as e:
                # Log other request exceptions (e.g., connection error) but don't create issues for them
                # unless it's a specific case like a 404 for security.txt (which is fine)
                # Check if response is available (it might not be in case of DNS failure etc)
                status_code_for_error = e.response.status_code if hasattr(e,
                                                                          'response') and e.response is not None else None
                if not (status_code_for_error == 404 and path == "/.well-known/security.txt"):
                    print(f"[A01AccessScanner] Error checking URL {full_url}: {e}")
                pass  # Or create an INFO issue if desired for logging purposes

        return issues
