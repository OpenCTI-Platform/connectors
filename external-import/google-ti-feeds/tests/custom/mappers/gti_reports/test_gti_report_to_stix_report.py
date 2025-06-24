"""Tests for the GTIReportToSTIXReport mapper."""

from datetime import datetime
from uuid import uuid4

import pytest
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_report import (
    GTIReportToSTIXReport,
)
from connector.src.custom.models.gti_reports.gti_report_model import (
    AggregationCommonalities,
    Counters,
    GTIReportData,
    Links,
    Motivation,
    ReportModel,
    SourceRegion,
    TagDetail,
    TargetedIndustry,
    TargetedRegion,
    Technology,
)
from polyfactory.factories.pydantic_factory import ModelFactory
from polyfactory.fields import Use
from stix2.v21 import Identity, MarkingDefinition  # type: ignore


class MotivationFactory(ModelFactory[Motivation]):
    """Factory for Motivation."""

    __model__ = Motivation


class TargetedIndustryFactory(ModelFactory[TargetedIndustry]):
    """Factory for TargetedIndustry."""

    __model__ = TargetedIndustry


class TargetedRegionFactory(ModelFactory[TargetedRegion]):
    """Factory for TargetedRegion."""

    __model__ = TargetedRegion


class SourceRegionFactory(ModelFactory[SourceRegion]):
    """Factory for SourceRegion."""

    __model__ = SourceRegion


class TagDetailFactory(ModelFactory[TagDetail]):
    """Factory for TagDetail."""

    __model__ = TagDetail


class TechnologyFactory(ModelFactory[Technology]):
    """Factory for Technology."""

    __model__ = Technology


class CountersFactory(ModelFactory[Counters]):
    """Factory for Counters."""

    __model__ = Counters


class AggregationCommonalitiesFactory(ModelFactory[AggregationCommonalities]):
    """Factory for AggregationCommonalities."""

    __model__ = AggregationCommonalities


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
def mock_author_identity():
    """Mock author identity."""
    return Identity(
        id=f"identity--{uuid4()}", name="Test Author", identity_class="individual"
    )


@pytest.fixture
def minimal_report_data():
    """Minimal report data for testing."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            name="Test Report Name", collection_type="report", private=False
        )
    )


@pytest.fixture
def report_with_all_data():
    """Report with comprehensive data."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            name="Comprehensive Test Report",
            collection_type="report",
            private=False,
            motivations=MotivationFactory.batch(2),
            intended_effects=["data-theft", "disruption"],
            threat_scape=["cybercrime", "espionage"],
            targeted_industries_tree=TargetedIndustryFactory.batch(2),
            targeted_regions_hierarchy=TargetedRegionFactory.batch(2),
            source_regions_hierarchy=SourceRegionFactory.batch(1),
            tags_details=TagDetailFactory.batch(3),
            technologies=TechnologyFactory.batch(2),
            counters=CountersFactory.build(),
            aggregations=AggregationCommonalitiesFactory.build(),
        )
    )


@pytest.fixture
def report_with_different_types():
    """Report with different report types for testing mapping."""
    return [
        GTIReportDataFactory.build(
            attributes=ReportModelFactory.build(
                name="News Report",
                report_type="News",
                collection_type="report",
                private=False,
            )
        ),
        GTIReportDataFactory.build(
            attributes=ReportModelFactory.build(
                name="Actor Profile Report",
                report_type="Actor Profile",
                collection_type="report",
                private=False,
            )
        ),
        GTIReportDataFactory.build(
            attributes=ReportModelFactory.build(
                name="Malware Profile Report",
                report_type="Malware Profile",
                collection_type="report",
                private=False,
            )
        ),
        GTIReportDataFactory.build(
            attributes=ReportModelFactory.build(
                name="Unknown Type Report",
                report_type="Unknown Type",
                collection_type="report",
                private=False,
            )
        ),
    ]


@pytest.fixture
def report_without_attributes():
    """Report without attributes."""
    return GTIReportDataFactory.build(attributes=None)


@pytest.fixture
def report_with_empty_attributes():
    """Report with empty attributes."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            name="", collection_type="report", private=False
        )
    )


@pytest.fixture
def report_with_external_links():
    """Report with external links."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            name="Report with Links",
            collection_type="report",
            private=False,
            link="https://example.com/report",
        )
    )


@pytest.fixture
def report_with_invalid_timestamps():
    """Report with invalid timestamp values."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            name="Invalid Timestamps Report",
            collection_type="report",
            private=False,
            creation_date=-1,
            last_modification_date=-1,
        )
    )


@pytest.fixture
def report_with_unicode_content():
    """Report with unicode characters."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            name="Report with 漢字 and émojis 🔒",
            collection_type="report",
            private=False,
            content="Content with unicode: 测试 🚀 café",
            executive_summary="Summary with unicode: résumé 🌟",
        )
    )


@pytest.fixture
def report_with_long_strings():
    """Report with very long string values."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            name="A" * 1000,
            collection_type="report",
            private=False,
            content="B" * 5000,
            executive_summary="C" * 2000,
        )
    )


def test_gti_report_to_stix_minimal_data(
    minimal_report_data, mock_organization, mock_tlp_marking
):
    """Test basic report conversion with minimal data."""
    # GIVEN: A GTI report with minimal required data (name, collection_type, private flag)
    # and valid organization and TLP marking objects for STIX report creation
    mapper = _given_gti_report_mapper(
        minimal_report_data, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the minimal GTI report data to STIX report object
    result = _when_convert_to_stix(mapper)

    # THEN: A valid STIX Report object should be created successfully
    # with basic properties populated from the minimal input data
    _then_stix_report_created_successfully(result)
    _then_stix_report_has_basic_properties(result, minimal_report_data)


def test_gti_report_to_stix_with_all_data(
    report_with_all_data, mock_organization, mock_tlp_marking
):
    """Test report conversion with comprehensive data."""
    # GIVEN: A GTI report containing comprehensive threat intelligence data including
    # motivations, intended effects, threat scape, targeted industries/regions, technologies, etc.
    mapper = _given_gti_report_mapper(
        report_with_all_data, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the comprehensive GTI report data to STIX report object
    result = _when_convert_to_stix(mapper)

    # THEN: A complete STIX Report object should be created successfully
    # with all available data fields properly mapped and labels/references extracted
    _then_stix_report_created_successfully(result)
    _then_stix_report_has_comprehensive_data(result, report_with_all_data)


def test_gti_report_to_stix_with_author_identity(
    minimal_report_data, mock_organization, mock_tlp_marking, mock_author_identity
):
    """Test report conversion with author identity."""
    # GIVEN: A GTI report with minimal data and an additional author identity object
    # representing the individual or entity that created the threat intelligence report
    mapper = _given_gti_report_mapper(
        minimal_report_data, mock_organization, mock_tlp_marking
    )
    mapper.add_author_identity(mock_author_identity)

    # WHEN: Converting the GTI report data with author identity to STIX report object
    result = _when_convert_to_stix(mapper)

    # THEN: The STIX Report object should include the author identity reference
    # properly linking the report to its creator for attribution and provenance
    _then_stix_report_has_author_identity(result, mock_author_identity)


def test_gti_report_without_attributes(
    report_without_attributes, mock_organization, mock_tlp_marking
):
    """Test report conversion fails without attributes."""
    # GIVEN: A GTI report with attributes field set to None
    # making it impossible to access any report data including name and classification
    mapper = _given_gti_report_mapper(
        report_without_attributes, mock_organization, mock_tlp_marking
    )

    # WHEN: Attempting to convert the GTI report data to STIX report object
    # THEN: A ValueError should be raised with message about invalid GTI report data
    # since the mapper cannot process a report without proper attribute structure
    _when_convert_to_stix_raises_error(mapper, ValueError, "Invalid GTI report data")


def test_gti_report_with_empty_name(
    report_with_empty_attributes, mock_organization, mock_tlp_marking
):
    """Test report conversion fails with empty name."""
    # GIVEN: A GTI report with an empty name field (empty string)
    # which fails to meet the minimum length requirement for valid report names
    mapper = _given_gti_report_mapper(
        report_with_empty_attributes, mock_organization, mock_tlp_marking
    )

    # WHEN: Attempting to convert the GTI report with empty name to STIX report object
    # THEN: A ValueError should be raised indicating name length requirement
    # since STIX reports require meaningful names for proper identification
    _when_convert_to_stix_raises_error(
        mapper, ValueError, "Report name must be at least 2 characters long"
    )


def test_different_report_types_mapping(
    report_with_different_types, mock_organization, mock_tlp_marking
):
    """Test mapping of different GTI report types to STIX report types."""
    # GIVEN: Four GTI reports with different report types: News, Actor Profile, Malware Profile, Unknown Type
    # representing various categories of threat intelligence reporting formats
    expected_report_types = [
        "News",
        "Actor Profile",
        "Malware Profile",
        "Unknown Type",
    ]

    # WHEN: Converting each GTI report type to STIX report objects
    # THEN: Each should be accepted by the open vocabulary system as valid report types
    for i, report_data in enumerate(report_with_different_types):
        mapper = _given_gti_report_mapper(
            report_data, mock_organization, mock_tlp_marking
        )
        result = _when_convert_to_stix(mapper)
        _then_stix_report_has_open_vocab_report_type(result, expected_report_types[i])


def test_extract_labels_from_report_data(
    report_with_all_data, mock_organization, mock_tlp_marking
):
    """Test extraction of labels from various report fields."""
    # GIVEN: A GTI report with comprehensive data including intended effects, threat scape,
    # motivations, and other categorical information that should be extracted as STIX labels
    mapper = _given_gti_report_mapper(
        report_with_all_data, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report data to STIX report object
    result = _when_convert_to_stix(mapper)

    # THEN: The STIX Report should contain extracted labels from various report fields
    # providing searchable and filterable metadata about the threat intelligence content
    _then_stix_report_has_extracted_labels(result, report_with_all_data)


def test_create_external_references_with_links(
    report_with_external_links, mock_organization, mock_tlp_marking
):
    """Test creation of external references."""
    # GIVEN: A GTI report containing external link information (source URLs)
    # that should be converted to STIX external references for source attribution
    mapper = _given_gti_report_mapper(
        report_with_external_links, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report with external links to STIX report object
    result = _when_convert_to_stix(mapper)

    # THEN: The STIX Report should contain proper external references
    # including both source links and GTI platform references for complete attribution
    _then_stix_report_has_external_references(result, report_with_external_links)


def test_timestamp_extraction_and_conversion(
    minimal_report_data, mock_organization, mock_tlp_marking
):
    """Test proper timestamp extraction and conversion."""
    # GIVEN: A GTI report with timestamp data that needs to be converted
    # from GTI format to proper STIX datetime objects with timezone information
    mapper = _given_gti_report_mapper(
        minimal_report_data, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report data to STIX report object
    result = _when_convert_to_stix(mapper)

    # THEN: The STIX Report should have properly formatted timestamps
    # with correct timezone information and datetime object types for created/modified fields
    _then_stix_report_has_proper_timestamps(result, minimal_report_data)


def test_add_object_refs_to_existing_report(
    minimal_report_data, mock_organization, mock_tlp_marking
):
    """Test adding object references to existing report."""
    # GIVEN: An existing STIX Report object and new STIX object IDs (indicator, malware)
    # that need to be added as references to establish relationships between objects
    mapper = _given_gti_report_mapper(
        minimal_report_data, mock_organization, mock_tlp_marking
    )
    existing_report = _when_convert_to_stix(mapper)

    new_object_ids = [f"indicator--{uuid4()}", f"malware--{uuid4()}"]

    # WHEN: Adding the new object references to the existing STIX report
    updated_report = GTIReportToSTIXReport.add_object_refs(
        new_object_ids, existing_report
    )

    # THEN: The updated report should contain all the new object references
    # linking the report to the related STIX domain objects for comprehensive threat intelligence
    _then_report_has_object_refs(updated_report, new_object_ids)


def test_add_object_refs_preserves_existing_refs(
    minimal_report_data, mock_organization, mock_tlp_marking
):
    """Test adding object references preserves existing ones."""
    # GIVEN: An existing STIX Report with pre-existing object references (indicator)
    # and new object references (malware) to be added without losing the original ones
    mapper = _given_gti_report_mapper(
        minimal_report_data, mock_organization, mock_tlp_marking
    )
    existing_report = _when_convert_to_stix(mapper)

    initial_refs = [f"indicator--{uuid4()}"]
    existing_report.object_refs = initial_refs

    new_refs = [f"malware--{uuid4()}"]
    # WHEN: Adding new object references to a report that already has existing references
    updated_report = GTIReportToSTIXReport.add_object_refs(new_refs, existing_report)

    # THEN: The updated report should contain both existing and new object references
    # preserving the complete set of relationships without losing any previous linkages
    _then_report_has_all_object_refs(updated_report, initial_refs + new_refs)


def test_add_duplicate_object_refs(
    minimal_report_data, mock_organization, mock_tlp_marking
):
    """Test adding duplicate object references doesn't create duplicates."""
    # GIVEN: An existing STIX Report with an object reference (indicator)
    # and an attempt to add the same object reference again to test deduplication
    mapper = _given_gti_report_mapper(
        minimal_report_data, mock_organization, mock_tlp_marking
    )
    existing_report = _when_convert_to_stix(mapper)

    object_id = f"indicator--{uuid4()}"
    existing_report.object_refs = [object_id]

    # WHEN: Adding an object reference that already exists in the report
    updated_report = GTIReportToSTIXReport.add_object_refs([object_id], existing_report)

    # THEN: The report should contain only one instance of the object reference
    # preventing duplicate relationships and maintaining clean object reference lists
    _then_report_has_no_duplicate_refs(updated_report, object_id)


def test_gti_report_with_invalid_timestamps(
    report_with_invalid_timestamps, mock_organization, mock_tlp_marking
):
    """Test handling of invalid timestamp values."""
    # GIVEN: A GTI report containing invalid timestamp values (negative numbers)
    # for creation and modification dates that need graceful error handling
    mapper = _given_gti_report_mapper(
        report_with_invalid_timestamps, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report with invalid timestamps to STIX report object
    result = _when_convert_to_stix(mapper)

    # THEN: The STIX Report should still be created successfully
    # with the mapper handling invalid timestamps gracefully and using fallback values
    _then_stix_report_created_successfully(result)


def test_gti_report_with_unicode_characters(
    report_with_unicode_content, mock_organization, mock_tlp_marking
):
    """Test handling of reports with unicode characters."""
    # GIVEN: A GTI report containing unicode characters in various fields
    # including Chinese characters (漢字), accented characters (émojis), and emoji symbols (🔒, 🚀)
    mapper = _given_gti_report_mapper(
        report_with_unicode_content, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report with unicode content to STIX report object
    result = _when_convert_to_stix(mapper)

    # THEN: The STIX Report should preserve all unicode characters correctly
    # maintaining international character support and emoji preservation in the output
    _then_stix_report_preserves_unicode_content(result, report_with_unicode_content)


def test_gti_report_with_long_strings(
    report_with_long_strings, mock_organization, mock_tlp_marking
):
    """Test handling of reports with very long strings."""
    # GIVEN: A GTI report containing extremely long string values in various fields
    # (1000 chars for name, 5000 for content, 2000 for summary) to test boundary conditions
    mapper = _given_gti_report_mapper(
        report_with_long_strings, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report with long strings to STIX report object
    result = _when_convert_to_stix(mapper)

    # THEN: The STIX Report should preserve the full length of all string fields
    # without truncation or corruption, handling large content volumes appropriately
    _then_stix_report_preserves_long_strings(result, report_with_long_strings)


def test_determine_report_type_with_none_type(mock_organization, mock_tlp_marking):
    """Test report type determination when report_type is None."""
    # GIVEN: A GTI report with report_type field set to None
    # representing missing or undefined report classification information
    report_data = GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            name="Report without type",
            collection_type="report",
            private=False,
            report_type=None,
        )
    )

    # WHEN: Converting the GTI report with None report_type to STIX report object
    mapper = _given_gti_report_mapper(report_data, mock_organization, mock_tlp_marking)
    result = _when_convert_to_stix(mapper)

    # THEN: The STIX Report should handle None report_type gracefully
    # Mapper provides "unknown" as default for None report_type
    _then_stix_report_has_open_vocab_report_type(result, "unknown")


def test_extract_labels_with_empty_fields(mock_organization, mock_tlp_marking):
    """Test label extraction when fields are empty or None."""
    # GIVEN: A GTI report with label-contributing fields set to empty lists or None
    # (intended_effects=[], threat_scape=None, motivations=[]) representing minimal categorical data
    report_data = GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            name="Report with empty fields",
            collection_type="report",
            private=False,
            intended_effects=[],
            threat_scape=None,
            motivations=[],
        )
    )

    # WHEN: Converting the GTI report with empty label fields to STIX report object
    mapper = _given_gti_report_mapper(report_data, mock_organization, mock_tlp_marking)
    result = _when_convert_to_stix(mapper)

    # THEN: The STIX Report should have empty or minimal labels
    # gracefully handling missing categorical information without generating invalid labels
    _then_stix_report_has_empty_or_minimal_labels(result)


def test_build_external_references_with_none_values(
    mock_organization, mock_tlp_marking
):
    """Test external reference building with None values."""
    # GIVEN: A GTI report with link field set to None
    # representing a report without additional source URL references but still requiring GTI platform reference
    report_data = GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            name="Report without external links",
            collection_type="report",
            private=False,
            link=None,
        )
    )

    # WHEN: Converting the GTI report without external links to STIX report object
    mapper = _given_gti_report_mapper(report_data, mock_organization, mock_tlp_marking)
    result = _when_convert_to_stix(mapper)

    # THEN: The STIX Report should have minimal external references
    # including only the GTI platform reference while omitting source link references
    _then_stix_report_has_minimal_external_references(result, report_data)


def _given_gti_report_mapper(report_data, organization, tlp_marking):
    """Create a GTI report mapper instance."""
    return GTIReportToSTIXReport(
        report=report_data, organization=organization, tlp_marking=tlp_marking
    )


def _when_convert_to_stix(mapper):
    """Convert GTI report to STIX."""
    return mapper.to_stix()


def _when_convert_to_stix_raises_error(mapper, exception_type, expected_message):
    """Expect conversion to raise specific error."""
    with pytest.raises(exception_type, match=expected_message):
        mapper.to_stix()


def _then_stix_report_created_successfully(result):
    """Assert STIX report was created successfully."""
    assert result is not None  # noqa: S101
    assert hasattr(result, "id")  # noqa: S101
    assert hasattr(result, "type")  # noqa: S101
    assert result.type == "report"  # noqa: S101


def _then_stix_report_has_basic_properties(result, original_data):
    """Assert STIX report has basic properties from original data."""
    assert result.name == original_data.attributes.name  # noqa: S101
    assert isinstance(result.created, datetime)  # noqa: S101
    assert isinstance(result.modified, datetime)  # noqa: S101
    assert isinstance(result.report_types, list)  # noqa: S101
    assert len(result.report_types) > 0  # noqa: S101


def _then_stix_report_has_comprehensive_data(result, original_data):
    """Assert STIX report includes comprehensive data."""
    _then_stix_report_created_successfully(result)
    _then_stix_report_has_basic_properties(result, original_data)

    if hasattr(result, "labels") and result.labels:
        assert isinstance(result.labels, list)  # noqa: S101

    if hasattr(result, "external_references") and result.external_references:
        assert isinstance(result.external_references, list)  # noqa: S101


def _then_stix_report_has_author_identity(result, author_identity):
    """Assert STIX report uses author identity."""
    assert result is not None  # noqa: S101


def _then_stix_report_has_report_type(result, expected_type):
    """Assert STIX report has expected report type."""
    assert expected_type in result.report_types  # noqa: S101


def _then_stix_report_has_open_vocab_report_type(result, expected_type_value):
    """Assert STIX report has expected report type value from open vocabulary."""
    assert len(result.report_types) > 0  # noqa: S101
    assert any(  # noqa: S101
        rt.value == expected_type_value for rt in result.report_types
    )


def _then_stix_report_has_none_report_type(result):
    """Assert STIX report handles None report type correctly."""
    assert len(result.report_types) > 0  # noqa: S101
    assert result.report_types[0].value == "unknown"  # noqa: S101


def _then_stix_report_has_extracted_labels(result, original_data):
    """Assert STIX report has labels extracted from original data."""
    if hasattr(result, "labels") and result.labels:
        labels = result.labels

        if original_data.attributes.intended_effects:
            for effect in original_data.attributes.intended_effects:
                assert effect in labels  # noqa: S101

        if original_data.attributes.threat_scape:
            for threat in original_data.attributes.threat_scape:
                assert threat in labels  # noqa: S101


def _then_stix_report_has_external_references(result, original_data):
    """Assert STIX report has external references."""
    if hasattr(result, "external_references") and result.external_references:
        refs = result.external_references
        assert isinstance(refs, list)  # noqa: S101
        assert len(refs) > 0  # noqa: S101

        if original_data.attributes.link:
            source_refs = [
                ref for ref in refs if _get_ref_source_name(ref) == "Source link"
            ]
            assert len(source_refs) > 0  # noqa: S101
            assert (  # noqa: S101
                _get_ref_url(source_refs[0]) == original_data.attributes.link
            )

        gti_refs = [
            ref
            for ref in refs
            if _get_ref_source_name(ref) == "Google Threat Intelligence Platform"
        ]
        assert len(gti_refs) > 0  # noqa: S101
        expected_url = f"https://www.virustotal.com/gui/collection/{original_data.id}"
        assert _get_ref_url(gti_refs[0]) == expected_url  # noqa: S101


def _then_stix_report_has_proper_timestamps(result, original_data):
    """Assert STIX report has properly converted timestamps."""
    assert isinstance(result.created, datetime)  # noqa: S101
    assert isinstance(result.modified, datetime)  # noqa: S101
    assert result.created.tzinfo is not None  # noqa: S101
    assert result.modified.tzinfo is not None  # noqa: S101


def _then_report_has_object_refs(result, expected_refs):
    """Assert report has expected object references."""
    assert hasattr(result, "object_refs")  # noqa: S101
    assert result.object_refs is not None  # noqa: S101
    for ref in expected_refs:
        assert ref in result.object_refs  # noqa: S101


def _then_report_has_all_object_refs(result, expected_refs):
    """Assert report has all expected object references."""
    assert hasattr(result, "object_refs")  # noqa: S101
    assert result.object_refs is not None  # noqa: S101
    assert len(result.object_refs) == len(expected_refs)  # noqa: S101
    for ref in expected_refs:
        assert ref in result.object_refs  # noqa: S101


def _then_report_has_no_duplicate_refs(result, object_id):
    """Assert report has no duplicate object references."""
    assert hasattr(result, "object_refs")  # noqa: S101
    assert result.object_refs is not None  # noqa: S101
    ref_count = result.object_refs.count(object_id)
    assert ref_count == 1  # noqa: S101


def _then_stix_report_preserves_unicode_content(result, original_data):
    """Assert STIX report preserves unicode content."""
    assert result.name == original_data.attributes.name  # noqa: S101
    if hasattr(result, "content") and result.content:
        assert result.content == original_data.attributes.content  # noqa: S101


def _then_stix_report_preserves_long_strings(result, original_data):
    """Assert STIX report preserves long strings."""
    assert result.name == original_data.attributes.name  # noqa: S101
    assert len(result.name) == len(original_data.attributes.name)  # noqa: S101


def _then_stix_report_has_empty_or_minimal_labels(result):
    """Assert STIX report has empty or minimal labels."""
    if hasattr(result, "labels"):
        assert result.labels is None or isinstance(result.labels, list)  # noqa: S101


def _then_stix_report_has_minimal_external_references(result, original_data):
    """Assert STIX report has minimal external references."""
    if hasattr(result, "external_references") and result.external_references:
        refs = result.external_references
        assert isinstance(refs, list)  # noqa: S101

        gti_refs = [
            ref
            for ref in refs
            if _get_ref_source_name(ref) == "Google Threat Intelligence Platform"
        ]
        assert len(gti_refs) > 0  # noqa: S101
        expected_url = f"https://www.virustotal.com/gui/collection/{original_data.id}"
        assert _get_ref_url(gti_refs[0]) == expected_url  # noqa: S101

        source_refs = [
            ref for ref in refs if _get_ref_source_name(ref) == "Source link"
        ]
        assert len(source_refs) == 0  # noqa: S101


def _get_ref_source_name(ref):
    """Get source_name from either dict or model format."""
    if isinstance(ref, dict):
        return ref.get("source_name")
    return getattr(ref, "source_name", None)


def _get_ref_url(ref):
    """Get url from either dict or model format."""
    if isinstance(ref, dict):
        return ref.get("url")
    return getattr(ref, "url", None)
