"""
Handles console reporting for WVS scanner results.
"""
import re
from typing import List
from wvs.scanner.models import Issue, Severity  # Assuming Severity is an Enum


class ConsoleReporter:
    """
    A reporter that prints scan findings to the console.
    """

    @staticmethod
    def _extract_cwe(references: List[str]) -> str:
        """
        Tries to extract a CWE ID from a list of reference URLs.
        Example: https://cwe.mitre.org/data/definitions/79.html -> CWE-79
        """
        cwe_pattern = re.compile(r"cwe.mitre.org/data/definitions/(\d+)\.html")
        for ref in references:
            match = cwe_pattern.search(ref)
            if match:
                return f"CWE-{match.group(1)}"
        return "N/A"

    @staticmethod
    def print_report(issues: List[Issue], verbose: bool = False) -> None:
        """
        Prints a formatted report of the issues to the console.

        Args:
            issues: A list of Issue objects.
            verbose: If True, prints more details like CVSS score and all references.
        """
        if not issues:
            print("No issues found.")
            return

        print("\n--- Vulnerability Report ---")
        # Sort issues by severity (e.g., Critical, High, Medium, Low, Info)
        # This requires Severity enum to have an order or be comparable.
        # If Severity is an Enum and has implicit order by definition, this works.
        # Otherwise, a custom sorting key would be needed.
        # For now, let's assume Severity values (like "Critical") can be mapped to an order.

        severity_order = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }

        try:
            sorted_issues = sorted(issues, key=lambda i: severity_order.get(i.severity, 0), reverse=True)
        except TypeError:  # Fallback if severity is not directly comparable or not always a Severity enum
            print("Warning: Could not sort issues by severity. Ensure all issues have a valid Severity enum value.")
            sorted_issues = issues

        for issue in sorted_issues:
            severity_val = issue.severity.value if isinstance(issue.severity, Severity) else str(issue.severity)
            print(f"\n[{severity_val.upper()}] {issue.name}")
            print(f"  - Description: {issue.description}")
            print(f"  - Recommendation: {issue.remediation}")

            cwe = ConsoleReporter._extract_cwe(issue.references)
            print(f"  - CWE: {cwe}")

            if verbose:
                if issue.cvss_score > 0:
                    print(f"  - CVSS Score: {issue.cvss_score} ({issue.cvss_vector})")
                if issue.id:
                    print(f"  - ID: {issue.id}")
                if issue.references:
                    print("  - References:")
                    for ref in issue.references:
                        # Avoid printing the CWE again if it was the only reference and already printed
                        if "cwe.mitre.org" in ref and cwe != "N/A":
                            if len(issue.references) == 1:
                                continue
                        print(f"    - {ref}")

        print("\n--- End of Report ---")


if __name__ == '__main__':
    # Example Usage (for testing this module directly)
    # Create some dummy Issue objects
    dummy_issues = [
        Issue(
            id="WVS-TEST-001",
            name="Cross-Site Scripting (XSS)",
            description="The application is vulnerable to XSS attacks due to unsanitized user input.",
            severity=Severity.HIGH,  # Using the Enum
            remediation="Sanitize all user inputs and use appropriate output encoding.",
            references=["https://owasp.org/www-community/attacks/xss/",
                        "https://cwe.mitre.org/data/definitions/79.html"],
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        ),
        Issue(
            id="WVS-TEST-002",
            name="SQL Injection",
            description="The application uses string concatenation to build SQL queries, making it vulnerable to SQL Injection.",
            severity=Severity.CRITICAL,
            remediation="Use parameterized queries or prepared statements.",
            references=["https://owasp.org/www-community/attacks/SQL_Injection",
                        "https://cwe.mitre.org/data/definitions/89.html"],
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        ),
        Issue(
            id="WVS-TEST-003",
            name="Weak Password Policy",
            description="The application allows weak passwords (e.g., less than 8 characters).",
            severity=Severity.MEDIUM,  # Using the Enum
            remediation="Enforce a strong password policy: minimum length, complexity, and rotation.",
            references=["https://cwe.mitre.org/data/definitions/521.html"],
            cvss_score=5.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        ),
        Issue(
            id="WVS-TEST-004",
            name="Informational Finding",
            description="Server version exposed in HTTP headers.",
            severity=Severity.INFO,  # Using the Enum
            remediation="Configure the web server to not reveal version information.",
            references=[],
        )
    ]

    print("--- Standard Report ---")
    ConsoleReporter.print_report(dummy_issues)

    print("\n--- Verbose Report ---")
    ConsoleReporter.print_report(dummy_issues, verbose=True)

    print("\n--- Report with No Issues ---")
    ConsoleReporter.print_report([])

    # Test with string severity (as might happen if from_dict isn't perfect or data is old)
    # This requires the Issue model's __post_init__ to handle string-to-enum conversion,
    # or the print_report to be robust against it.
    # My Issue model has a __post_init__ that should handle this.
    print("\n--- Report with mixed Severity types (if models.py handles conversion) ---")
    dummy_issues_mixed_severity = [
        Issue.from_dict({
            "id": "WVS-TEST-005",
            "name": "Mixed Severity Test",
            "description": "Issue with severity as string.",
            "severity": "Low",  # String severity
            "remediation": "Fix it.",
            "references": []
        })
    ]
    ConsoleReporter.print_report(dummy_issues_mixed_severity, verbose=True)
