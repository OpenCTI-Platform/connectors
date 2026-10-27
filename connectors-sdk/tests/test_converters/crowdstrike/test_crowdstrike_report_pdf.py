# pragma: no cover # Do not compute coverage on test files
"""Offer tests for CrowdStrikeReportPdfConverter."""

import pytest
from connectors_sdk.converters.crowdstrike import (
    CrowdStrikeReportPdf,
    CrowdStrikeReportPdfConverter,
)
from connectors_sdk.models import Artifact, OrganizationAuthor, TLPMarking

PDF = b"%PDF-1.7 monthly threat report"


@pytest.fixture
def converter() -> CrowdStrikeReportPdfConverter:
    """Return a converter."""
    return CrowdStrikeReportPdfConverter(
        author=OrganizationAuthor(name="CrowdStrike"),
        markings=[TLPMarking(level="amber")],
    )


def test_report_pdf_becomes_an_artifact(
    converter: CrowdStrikeReportPdfConverter,
) -> None:
    """Test that the PDF becomes one artifact with its content, type and name."""
    pdf = CrowdStrikeReportPdf(
        report_id=123, file_name="monthly-threat-report.pdf", content=PDF
    )

    (artifact,) = converter.transform(pdf)

    assert isinstance(artifact, Artifact)
    assert artifact.content == PDF
    assert artifact.mime_type == "application/pdf"
    assert artifact.additional_names == ["monthly-threat-report.pdf"]


def test_author_and_markings(converter: CrowdStrikeReportPdfConverter) -> None:
    """Test that the artifact references the author and markings."""
    pdf = CrowdStrikeReportPdf(report_id=123, file_name="report.pdf", content=PDF)

    stix = converter.transform(pdf)[0].to_stix2_object()

    assert stix["x_opencti_created_by_ref"] == converter.author.id
    assert stix["object_marking_refs"] == [converter.markings[0].id]


def test_same_pdf_for_two_reports_gives_one_artifact(
    converter: CrowdStrikeReportPdfConverter,
) -> None:
    """Test that the artifact id only depends on the content."""
    first = CrowdStrikeReportPdf(report_id=123, file_name="first.pdf", content=PDF)
    second = CrowdStrikeReportPdf(report_id=456, file_name="second.pdf", content=PDF)

    assert converter.transform(first)[0].id == converter.transform(second)[0].id
