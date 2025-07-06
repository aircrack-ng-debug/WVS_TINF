import json
from dataclasses import asdict
from typing import List
from wvs.scanner.models import Issue # Annahme: Issue-Modell ist hier

class JsonReporter:
    """
    Generates a JSON report from a list of issues.
    """

    @staticmethod
    def write_report(issues: List[Issue], filename: str) -> None:
        """
        Writes the list of Issue objects to a JSON file.

        Args:
            issues: A list of Issue objects.
            filename: The name of the file to write the JSON report to.
        """
        report_data = [asdict(issue) for issue in issues]
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=4, ensure_ascii=False)
            print(f"JSON report successfully written to {filename}")
        except IOError as e:
            print(f"Error writing JSON report to {filename}: {e}")
        except TypeError as e:
            print(f"Error serializing an issue to JSON: {e}. Ensure all fields in Issue are JSON serializable.")

if __name__ == '__main__':
    # Example Usage (for testing purposes)
    # Assuming Issue is a dataclass or can be converted by asdict
    from dataclasses import dataclass

    @dataclass
    class MockIssue:
        id: str
        name: str
        severity: str
        description: str
        url: str
        remediation: str

    mock_issues = [
        MockIssue(
            id="CVE-2023-1234",
            name="SQL Injection",
            severity="High",
            description="A SQL injection vulnerability was found in the login form.",
            url="https://example.com/login",
            remediation="Use parameterized queries."
        ),
        MockIssue(
            id="CVE-2023-5678",
            name="Cross-Site Scripting (XSS)",
            severity="Medium",
            description="A XSS vulnerability was found on the search results page.",
            url="https://example.com/search?q=<script>alert(1)</script>",
            remediation="Sanitize user input."
        )
    ]
    JsonReporter.write_report(mock_issues, "example_report.json")
    print("Created example_report.json for testing.")

    # Test with empty list
    JsonReporter.write_report([], "empty_report.json")
    print("Created empty_report.json for testing.")

    # Test with non-serializable data (if Issue had complex types not handled by asdict)
    # This part would require a more complex MockIssue or a real Issue object
    # For now, we trust that asdict handles standard types in Issue.
    # If Issue contains e.g. datetime objects, they might need custom handling in a real scenario.
    # print("Testing with potentially non-serializable data...")
    # class NonSerializable:
    #     pass
    # mock_issues_complex = [
    #     MockIssue(
    #         id="CMPLX-001",
    #         name="Complex Issue",
    #         severity="Low",
    #         description=NonSerializable(), # This would cause a TypeError
    #         url="https://example.com/complex",
    #         remediation="Fix it."
    #     )
    # ]
    # JsonReporter.write_report(mock_issues_complex, "complex_error_report.json")
    # print("Finished testing complex data serialization.")
