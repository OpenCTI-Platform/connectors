"""Tests for the content of reports: executive summary and report body."""

import pytest
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_report import (
    GTIReportToSTIXReport,
)
from connector.src.custom.models.gti.gti_report_model import ReportModel


def _attributes(content: str | None, executive_summary: str | None) -> ReportModel:
    return ReportModel.model_construct(
        content=content, executive_summary=executive_summary
    )


def test_executive_summary_precedes_content() -> None:
    """The GTI executive summary is shown before the report content."""
    # Given a report with an executive summary in Markdown and HTML content
    attributes = _attributes("<p>Body</p>", "- Key point")
    # When its content is built
    content = GTIReportToSTIXReport._build_content(attributes)
    # Then the summary comes first, converted to HTML
    assert content == (  # noqa: S101
        "<h1>Executive Summary</h1>\n<ul>\n<li>Key point</li>\n</ul>\n\n"
        "<h1>Report Content</h1>\n<p>Body</p>"
    )


@pytest.mark.parametrize(
    "content, executive_summary, expected",
    [
        ("<p>Body</p>", None, "<p>Body</p>"),
        ("<p>Body</p>", "  ", "<p>Body</p>"),
        (None, "<p>Summary</p>", "<h1>Executive Summary</h1>\n<p>Summary</p>"),
        (None, None, ""),
    ],
)
def test_content_without_summary_or_body(
    content: str | None, executive_summary: str | None, expected: str
) -> None:
    """Missing parts are left out, without empty headings."""
    # Given a report missing its summary or its body
    attributes = _attributes(content, executive_summary)
    # When its content is built
    # Then only the available parts are shown
    assert GTIReportToSTIXReport._build_content(attributes) == expected  # noqa: S101
