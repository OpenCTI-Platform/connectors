"""Tests for analyst_comment Note creation in GTIReportToSTIXComposite mapper."""

from uuid import uuid4

import pytest
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_composite import (
    GTIReportToSTIXComposite,
)
from connector.src.custom.models.gti.gti_report_model import (
    GTIReportData,
    Links,
    ReportModel,
)
from polyfactory.factories.pydantic_factory import ModelFactory
from polyfactory.fields import Use
from stix2.v21 import Identity, MarkingDefinition  # type: ignore


class LinksFactory(ModelFactory[Links]):
    """Factory for Links."""

    __model__ = Links


class ReportModelFactory(ModelFactory[ReportModel]):
    """Factory for ReportModel."""

    __model__ = ReportModel

    collection_type = "report"
    private = False


class GTIReportDataFactory(ModelFactory[GTIReportData]):
    """Factory for GTIReportData."""

    __model__ = GTIReportData

    type = "report"
    attributes = Use(ReportModelFactory.build)
    links = Use(LinksFactory.build)


@pytest.fixture
def mock_organization():
    """Mock organization identity."""
    return Identity(
        id=f"identity--{uuid4()}",
        name="Test Organization",
        identity_class="organization",
    )


@pytest.fixture
def mock_tlp_marking():
    """Mock TLP marking definition."""
    return MarkingDefinition(
        id=f"marking-definition--{uuid4()}",
        definition_type="statement",
        definition={"statement": "Internal Use Only"},
    )


@pytest.fixture
def report_with_analyst_comment():
    """Report with an analyst_comment field populated."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            name="News Analysis Report",
            collection_type="report",
            private=False,
            report_type="News Analysis",
            analyst_comment="This is an analyst comment with expert commentary.",
        )
    )


@pytest.fixture
def report_without_analyst_comment():
    """Report without an analyst_comment field."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            name="Standard Report",
            collection_type="report",
            private=False,
            report_type="Threat Activity Report",
            analyst_comment=None,
        )
    )


@pytest.fixture
def report_with_empty_analyst_comment():
    """Report with an empty analyst_comment field."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            name="Report with empty comment",
            collection_type="report",
            private=False,
            analyst_comment="",
        )
    )


def _given_composite_mapper(report_data, organization, tlp_marking):
    """Create a GTI report composite mapper instance."""
    return GTIReportToSTIXComposite(
        report=report_data, organization=organization, tlp_marking=tlp_marking
    )


def _when_convert_to_stix(mapper):
    """Convert GTI report to STIX via composite mapper."""
    return mapper.to_stix()


def _find_notes(stix_entities):
    """Find all note objects in the STIX entity list."""
    return [e for e in stix_entities if hasattr(e, "type") and e.type == "note"]


def _find_report(stix_entities):
    """Find the report object in the STIX entity list."""
    reports = [e for e in stix_entities if hasattr(e, "type") and e.type == "report"]
    return reports[0] if reports else None


@pytest.mark.order(1)
def test_analyst_comment_creates_note(
    report_with_analyst_comment, mock_organization, mock_tlp_marking
):
    """Test that a Note is created when analyst_comment is present."""
    # GIVEN: A GTI report of type "News Analysis" with an analyst_comment field populated
    mapper = _given_composite_mapper(
        report_with_analyst_comment, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the report to STIX entities
    result = _when_convert_to_stix(mapper)

    # THEN: A Note STIX object should be present in the output
    notes = _find_notes(result)
    assert len(notes) == 1  # noqa: S101


@pytest.mark.order(1)
def test_analyst_comment_note_content(
    report_with_analyst_comment, mock_organization, mock_tlp_marking
):
    """Test that the Note content matches the analyst_comment value."""
    # GIVEN: A GTI report with a specific analyst_comment
    mapper = _given_composite_mapper(
        report_with_analyst_comment, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the report to STIX entities
    result = _when_convert_to_stix(mapper)

    # THEN: The Note content should match the analyst_comment field
    note = _find_notes(result)[0]
    assert (
        note.content == "This is an analyst comment with expert commentary."
    )  # noqa: S101


@pytest.mark.order(1)
def test_analyst_comment_note_abstract(
    report_with_analyst_comment, mock_organization, mock_tlp_marking
):
    """Test that the Note abstract follows the expected naming convention."""
    # GIVEN: A GTI report named "News Analysis Report" with an analyst_comment
    mapper = _given_composite_mapper(
        report_with_analyst_comment, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the report to STIX entities
    result = _when_convert_to_stix(mapper)

    # THEN: The Note abstract should follow the pattern:
    # "Analyst Comment & News Analysis Rating - {report_name}"
    note = _find_notes(result)[0]
    assert (
        note.abstract == "Analyst Comment & News Analysis Rating - News Analysis Report"
    )  # noqa: S101


@pytest.mark.order(1)
def test_analyst_comment_note_references_report(
    report_with_analyst_comment, mock_organization, mock_tlp_marking
):
    """Test that the Note object_refs points to the parent Report."""
    # GIVEN: A GTI report with an analyst_comment
    mapper = _given_composite_mapper(
        report_with_analyst_comment, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the report to STIX entities
    result = _when_convert_to_stix(mapper)

    # THEN: The Note's object_refs should contain the Report's ID
    note = _find_notes(result)[0]
    report = _find_report(result)
    assert report is not None  # noqa: S101
    assert report.id in note.object_refs  # noqa: S101


@pytest.mark.order(1)
def test_no_note_without_analyst_comment(
    report_without_analyst_comment, mock_organization, mock_tlp_marking
):
    """Test that no Note is created when analyst_comment is None."""
    # GIVEN: A GTI report without an analyst_comment field
    mapper = _given_composite_mapper(
        report_without_analyst_comment, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the report to STIX entities
    result = _when_convert_to_stix(mapper)

    # THEN: No Note STIX object should be present in the output
    notes = _find_notes(result)
    assert len(notes) == 0  # noqa: S101


@pytest.mark.order(1)
def test_no_note_with_empty_analyst_comment(
    report_with_empty_analyst_comment, mock_organization, mock_tlp_marking
):
    """Test that no Note is created when analyst_comment is an empty string."""
    # GIVEN: A GTI report with an empty analyst_comment field
    mapper = _given_composite_mapper(
        report_with_empty_analyst_comment, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the report to STIX entities
    result = _when_convert_to_stix(mapper)

    # THEN: No Note STIX object should be present in the output
    notes = _find_notes(result)
    assert len(notes) == 0  # noqa: S101


@pytest.mark.order(1)
def test_analyst_comment_note_has_deterministic_id(
    report_with_analyst_comment, mock_organization, mock_tlp_marking
):
    """Test that the Note has a deterministic ID (generated via pycti)."""
    # GIVEN: A GTI report with an analyst_comment
    mapper1 = _given_composite_mapper(
        report_with_analyst_comment, mock_organization, mock_tlp_marking
    )
    mapper2 = _given_composite_mapper(
        report_with_analyst_comment, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the same report twice
    result1 = _when_convert_to_stix(mapper1)
    result2 = _when_convert_to_stix(mapper2)

    # THEN: Both Notes should have the same deterministic ID
    note1 = _find_notes(result1)[0]
    note2 = _find_notes(result2)[0]
    assert note1.id == note2.id  # noqa: S101
    assert note1.id.startswith("note--")  # noqa: S101
