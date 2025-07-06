from typing import List
from wvs.scanner.models import Issue  # Assuming Issue model path

# ReportLab imports
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY


class PdfReporter:
    """
    Generates a PDF report from a list of issues.
    """

    @staticmethod
    def write_report(issues: List[Issue], filename: str) -> None:
        """
        Writes the list of Issue objects to a PDF file.

        Args:
            issues: A list of Issue objects.
            filename: The name of the file to write the PDF report to.
        """
        try:
            doc = SimpleDocTemplate(filename, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []

            # Title
            title_style = styles['h1']
            title_style.alignment = TA_CENTER
            title_text = "WVS Security Scan Report"
            story.append(Paragraph(title_text, title_style))
            story.append(Spacer(1, 0.5 * inch))

            if not issues:
                story.append(Paragraph("No security issues found.", styles['Normal']))
            else:
                story.append(Paragraph(f"Found {len(issues)} issue(s):", styles['h2']))
                story.append(Spacer(1, 0.2 * inch))

                for issue in issues:
                    # Issue Title (using the issue's name)
                    story.append(Paragraph(f"Issue: {issue.name}", styles['h3']))
                    story.append(Spacer(1, 0.1 * inch))

                    # Severity
                    story.append(Paragraph(f"<b>Severity:</b> {issue.severity.value}", styles['Normal']))

                    # URL
                    if hasattr(issue, 'url') and issue.url:  # Check if url attribute exists and is not empty
                        story.append(Paragraph(f"<b>URL:</b> {issue.url}", styles['Normal']))

                    # Description
                    desc_style = styles['Normal']
                    desc_style.alignment = TA_JUSTIFY
                    story.append(Paragraph(f"<b>Description:</b> {issue.description}", desc_style))

                    # Remediation
                    if issue.remediation:
                        story.append(Paragraph(f"<b>Remediation:</b> {issue.remediation}", desc_style))

                    story.append(Spacer(1, 0.3 * inch))
                    # Optional: Add a PageBreak between issues if reports are very long
                    # story.append(PageBreak())

            doc.build(story)
            print(f"PDF report successfully written to {filename}")

        except Exception as e:
            print(f"Error writing PDF report to {filename}: {e}")


if __name__ == '__main__':
    # This section is for basic, standalone testing of the PdfReporter.
    # To run this, you would execute `python -m wvs.reporting.pdf_reporter`
    # from the project root.
    # It requires the actual Issue and Severity objects from wvs.scanner.models.

    from wvs.scanner.models import Issue, Severity  # Import actual models

    print("Running PdfReporter standalone test...")

    # Example issues using the actual Issue model
    mock_issues_for_pdf = [
        Issue(
            id="TEST-001",
            name="Test Vulnerability One",
            description="This is a test description for the first vulnerability. It should be detailed enough to demonstrate text wrapping and formatting within the PDF.",
            severity=Severity.HIGH,
            remediation="Apply patches and update system configurations. Follow best practices for secure coding.",
            references=["http://example.com/ref1"],
            url="http://target.example.com/vuln1",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        ),
        Issue(
            id="TEST-002",
            name="Another Test Vulnerability (Medium)",
            description="This describes another issue found during scanning. This one is of medium severity and has a shorter remediation.",
            severity=Severity.MEDIUM,
            remediation="Review code and sanitize inputs.",
            references=[],
            url="http://target.example.com/vuln2",
            cvss_score=5.0,
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N"
        ),
        Issue(
            id="INFO-001",
            name="Informational Finding",
            description="This is an informational finding, not a direct vulnerability, but good to know.",
            severity=Severity.INFO,
            remediation="No specific remediation required, for awareness.",
            references=[],
            url="http://target.example.com/info1"
        ),
    ]

    # Test with issues
    PdfReporter.write_report(mock_issues_for_pdf, "test_report_generated.pdf")
    print("Generated 'test_report_generated.pdf' with sample issues.")

    # Test with an empty list of issues
    PdfReporter.write_report([], "empty_test_report_generated.pdf")
    print("Generated 'empty_test_report_generated.pdf' for the case of no issues.")

    print("PdfReporter standalone test finished.")
