"""Tests for the GTIReportToSTIXSector mapper."""

from uuid import uuid4

import pytest
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_sector import (
    GTIReportToSTIXSector,
)
from connector.src.custom.models.gti_reports.gti_report_model import (
    GTIReportData,
    Links,
    ReportModel,
    TargetedIndustry,
)
from polyfactory.factories.pydantic_factory import ModelFactory
from polyfactory.fields import Use
from stix2.v21 import Identity, MarkingDefinition  # type: ignore


class LinksFactory(ModelFactory[Links]):
    """Factory for Links model."""

    __model__ = Links


class TargetedIndustryFactory(ModelFactory[TargetedIndustry]):
    """Factory for TargetedIndustry model."""

    __model__ = TargetedIndustry


class ReportModelFactory(ModelFactory[ReportModel]):
    """Factory for ReportModel."""

    __model__ = ReportModel


class GTIReportDataFactory(ModelFactory[GTIReportData]):
    """Factory for GTIReportData."""

    __model__ = GTIReportData

    type = "report"
    attributes = Use(ReportModelFactory.build)


@pytest.fixture
def mock_organization():
    """Mock organization Identity object."""
    return Identity(  # pylint: disable=W9101  # it's a test no real ingest
        name="Test Organization",
        identity_class="organization",
    )


@pytest.fixture
def mock_tlp_marking():
    """Mock TLP marking definition object."""
    return MarkingDefinition(
        id=f"marking-definition--{uuid4()}",
        definition_type="statement",
        definition={"statement": "Internal Use Only"},
    )


@pytest.fixture
def report_with_single_industry() -> GTIReportData:
    """Fixture for GTI report with a single targeted industry."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            targeted_industries_tree=[
                TargetedIndustryFactory.build(
                    industry_group="Technology",
                    industry="Software Development",
                    confidence="High",
                )
            ]
        )
    )


@pytest.fixture
def report_with_multiple_industries() -> GTIReportData:
    """Fixture for GTI report with multiple targeted industries."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            targeted_industries_tree=[
                TargetedIndustryFactory.build(
                    industry_group="Financial Services",
                    industry="Banking",
                    confidence="High",
                ),
                TargetedIndustryFactory.build(
                    industry_group="Healthcare",
                    industry="Hospitals",
                    confidence="Medium",
                ),
                TargetedIndustryFactory.build(
                    industry_group="Energy",
                    industry="Oil & Gas",
                    confidence="Low",
                ),
            ]
        )
    )


@pytest.fixture
def report_without_industries() -> GTIReportData:
    """Fixture for GTI report without targeted industries."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(targeted_industries_tree=None)
    )


@pytest.fixture
def report_with_empty_industries() -> GTIReportData:
    """Fixture for GTI report with empty targeted industries list."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(targeted_industries_tree=[])
    )


@pytest.fixture
def report_without_attributes() -> GTIReportData:
    """Fixture for GTI report without attributes."""
    return GTIReportDataFactory.build(attributes=None)


@pytest.fixture
def report_with_industry_without_group() -> GTIReportData:
    """Fixture for GTI report with industry missing industry_group."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            targeted_industries_tree=[
                TargetedIndustryFactory.build(
                    industry_group="",
                    industry="Software Development",
                    confidence="High",
                )
            ]
        )
    )


@pytest.fixture
def report_with_industry_with_none_group() -> GTIReportData:
    """Fixture for GTI report with industry having None industry_group."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            targeted_industries_tree=[
                TargetedIndustryFactory.build(
                    industry_group="",
                    industry="Software Development",
                    confidence="High",
                )
            ]
        )
    )


@pytest.fixture
def report_with_mixed_valid_invalid_industries() -> GTIReportData:
    """Fixture for GTI report with mix of valid and invalid industries."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            targeted_industries_tree=[
                TargetedIndustryFactory.build(
                    industry_group="Technology",
                    industry="Software Development",
                    confidence="High",
                ),
                TargetedIndustryFactory.build(
                    industry_group="",
                    industry="Banking",
                    confidence="Medium",
                ),
                TargetedIndustryFactory.build(
                    industry_group="Healthcare",
                    industry="Hospitals",
                    confidence="Low",
                ),
            ]
        )
    )


@pytest.fixture
def report_with_long_industry_names() -> GTIReportData:
    """Fixture for GTI report with very long industry names."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            targeted_industries_tree=[
                TargetedIndustryFactory.build(
                    industry_group="A" * 500,
                    industry="B" * 1000,
                    confidence="High",
                )
            ]
        )
    )


@pytest.fixture
def report_with_special_characters() -> GTIReportData:
    """Fixture for GTI report with special characters in industry names."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            targeted_industries_tree=[
                TargetedIndustryFactory.build(
                    industry_group="Technology & Software",
                    industry="Web Development & Design",
                    confidence="High",
                )
            ]
        )
    )


def test_gti_report_to_stix_sector_single_industry(
    report_with_single_industry, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report with single targeted industry to STIX sector."""
    # GIVEN: A GTI report containing a single targeted industry (Technology/Software Development)
    # and valid organization and TLP marking objects for STIX creation
    mapper = _given_gti_report_sector_mapper(
        report_with_single_industry, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report data to STIX sector objects
    sectors = _when_convert_to_stix(mapper)

    # THEN: Exactly one STIX Identity sector object should be created
    # with correct properties matching the industry group from the report
    _then_stix_sectors_created_successfully(sectors, 1)
    _then_stix_sector_has_correct_properties(
        sectors[0], "Technology", mock_organization, mock_tlp_marking
    )


def test_gti_report_to_stix_sector_multiple_industries(
    report_with_multiple_industries, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report with multiple targeted industries to STIX sectors."""
    # GIVEN: A GTI report containing multiple targeted industries (Financial Services, Healthcare, Energy)
    # each with different confidence levels and valid organization/TLP marking for STIX creation
    mapper = _given_gti_report_sector_mapper(
        report_with_multiple_industries, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report data to STIX sector objects
    sectors = _when_convert_to_stix(mapper)

    # THEN: Three STIX Identity sector objects should be created, one for each industry group
    # maintaining the original order and proper STIX properties for each sector
    _then_stix_sectors_created_successfully(sectors, 3)
    expected_names = ["Financial Services", "Healthcare", "Energy"]
    for i, sector in enumerate(sectors):
        _then_stix_sector_has_correct_properties(
            sector, expected_names[i], mock_organization, mock_tlp_marking
        )


def test_gti_report_to_stix_sector_without_industries(
    report_without_industries, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report without targeted industries."""
    # Given
    mapper = _given_gti_report_sector_mapper(
        report_without_industries, mock_organization, mock_tlp_marking
    )

    # When
    sectors = _when_convert_to_stix(mapper)

    # Then
    _then_stix_sectors_created_successfully(sectors, 0)


def test_gti_report_to_stix_sector_empty_industries(
    report_with_empty_industries, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report with empty targeted industries list."""
    # GIVEN: A GTI report with targeted_industries_tree set to an empty list
    # indicating that industry targeting was considered but no specific industries were identified
    mapper = _given_gti_report_sector_mapper(
        report_with_empty_industries, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report data to STIX sector objects
    sectors = _when_convert_to_stix(mapper)

    # THEN: No STIX Identity sector objects should be created
    # since the empty list contains no industries to process
    _then_stix_sectors_created_successfully(sectors, 0)


def test_gti_report_to_stix_sector_without_attributes(
    report_without_attributes, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report without attributes raises ValueError."""
    # GIVEN: A GTI report with attributes set to None
    # making it impossible to access any report data including industries
    mapper = _given_gti_report_sector_mapper(
        report_without_attributes, mock_organization, mock_tlp_marking
    )

    # WHEN: Attempting to convert the GTI report data to STIX sector objects
    # THEN: A ValueError should be raised with message about invalid attributes
    # since the mapper cannot process a report without proper attribute structure
    _when_convert_to_stix_raises_error(mapper, ValueError, "Invalid report attributes")


def test_gti_report_to_stix_sector_industry_without_group(
    report_with_industry_without_group, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report with industry missing industry_group."""
    # GIVEN: A GTI report containing an industry with empty industry_group field
    # but valid industry name, simulating incomplete industry data
    mapper = _given_gti_report_sector_mapper(
        report_with_industry_without_group, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report data to STIX sector objects
    sectors = _when_convert_to_stix(mapper)

    # THEN: No STIX Identity sector objects should be created
    # since industry_group is required for sector creation and empty groups are filtered out
    _then_stix_sectors_created_successfully(sectors, 0)


def test_gti_report_to_stix_sector_industry_with_none_group(
    report_with_industry_with_none_group, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report with industry having None industry_group."""
    # GIVEN: A GTI report containing an industry with industry_group effectively None (empty string)
    # representing missing or null industry group classification
    mapper = _given_gti_report_sector_mapper(
        report_with_industry_with_none_group, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report data to STIX sector objects
    sectors = _when_convert_to_stix(mapper)

    # THEN: No STIX Identity sector objects should be created
    # since None/empty industry_group values are invalid for sector creation
    _then_stix_sectors_created_successfully(sectors, 0)


def test_gti_report_to_stix_sector_mixed_valid_invalid_industries(
    report_with_mixed_valid_invalid_industries, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report with mix of valid and invalid industries."""
    # GIVEN: A GTI report containing three industries: two with valid industry_group values
    # (Technology, Healthcare) and one with empty industry_group (invalid)
    mapper = _given_gti_report_sector_mapper(
        report_with_mixed_valid_invalid_industries, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report data to STIX sector objects
    sectors = _when_convert_to_stix(mapper)

    # THEN: Only two STIX Identity sector objects should be created for valid industries
    # while invalid industries with empty groups are filtered out during processing
    _then_stix_sectors_created_successfully(sectors, 2)
    expected_names = ["Technology", "Healthcare"]
    for i, sector in enumerate(sectors):
        _then_stix_sector_has_correct_properties(
            sector, expected_names[i], mock_organization, mock_tlp_marking
        )


def test_gti_report_to_stix_sector_long_industry_names(
    report_with_long_industry_names, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report with very long industry names."""
    # GIVEN: A GTI report containing an industry with extremely long names
    # (500 characters for industry_group, 1000 for industry) to test boundary conditions
    mapper = _given_gti_report_sector_mapper(
        report_with_long_industry_names, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report data to STIX sector objects
    sectors = _when_convert_to_stix(mapper)

    # THEN: One STIX Identity sector object should be created successfully
    # preserving the full length of the industry_group name without truncation
    _then_stix_sectors_created_successfully(sectors, 1)
    _then_stix_sector_preserves_long_names(sectors[0])


def test_gti_report_to_stix_sector_special_characters(
    report_with_special_characters, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report with special characters in industry names."""
    # GIVEN: A GTI report containing an industry with special characters in names
    # (ampersands, spaces) to test character encoding and preservation
    mapper = _given_gti_report_sector_mapper(
        report_with_special_characters, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report data to STIX sector objects
    sectors = _when_convert_to_stix(mapper)

    # THEN: One STIX Identity sector object should be created successfully
    # preserving all special characters in the industry_group name without modification
    _then_stix_sectors_created_successfully(sectors, 1)
    _then_stix_sector_preserves_special_characters(sectors[0])


def test_process_industry_with_valid_data(mock_organization, mock_tlp_marking):
    """Test _process_industry method with valid industry data."""
    # GIVEN: A mapper instance and a valid TargetedIndustry object
    # with complete industry_group and industry fields
    report = GTIReportDataFactory.build()
    mapper = _given_gti_report_sector_mapper(
        report, mock_organization, mock_tlp_marking
    )

    industry_data = TargetedIndustryFactory.build(
        industry_group="Technology",
        industry="Software Development",
    )

    # WHEN: Processing the industry data through the _process_industry method
    sector = mapper._process_industry(industry_data)

    # THEN: A valid STIX Identity sector object should be returned
    # with the name matching the industry_group from the input data
    assert sector is not None  # noqa: S101
    assert sector.name == "Technology"  # noqa: S101


def test_process_industry_with_empty_group(mock_organization, mock_tlp_marking):
    """Test _process_industry method with empty industry_group."""
    # GIVEN: A mapper instance and a TargetedIndustry object
    # with empty industry_group but valid industry field
    report = GTIReportDataFactory.build()
    mapper = _given_gti_report_sector_mapper(
        report, mock_organization, mock_tlp_marking
    )

    industry_data = TargetedIndustryFactory.build(
        industry_group="",
        industry="Software Development",
    )

    # WHEN: Processing the industry data through the _process_industry method
    sector = mapper._process_industry(industry_data)

    # THEN: No sector object should be returned (None)
    # since empty industry_group values are considered invalid
    assert sector is None  # noqa: S101


def test_process_industry_with_none_group(mock_organization, mock_tlp_marking):
    """Test _process_industry method with empty industry_group (simulating None)."""
    # GIVEN: A mapper instance and a TargetedIndustry object
    # with industry_group simulating None value (empty string) but valid industry field
    report = GTIReportDataFactory.build()
    mapper = _given_gti_report_sector_mapper(
        report, mock_organization, mock_tlp_marking
    )

    industry_data = TargetedIndustryFactory.build(
        industry_group="",
        industry="Software Development",
    )

    # WHEN: Processing the industry data through the _process_industry method
    sector = mapper._process_industry(industry_data)

    # THEN: No sector object should be returned (None)
    # since None-equivalent industry_group values are filtered out
    assert sector is None  # noqa: S101


def test_create_sector_with_description(mock_organization, mock_tlp_marking):
    """Test _create_sector method includes description when available."""
    # GIVEN: A mapper instance and a TargetedIndustry object
    # with both industry_group and description fields populated
    report = GTIReportDataFactory.build()
    mapper = _given_gti_report_sector_mapper(
        report, mock_organization, mock_tlp_marking
    )

    industry_data = TargetedIndustryFactory.build(
        industry_group="Technology",
        description="Technology sector including software and hardware companies",
    )

    # WHEN: Creating a sector object through the _create_sector method
    sector = mapper._create_sector(industry_data)

    # THEN: The sector should have the correct name and include the description
    # preserving both the industry_group as name and description field content
    assert sector.name == "Technology"  # noqa: S101
    assert (  # noqa: S101
        sector.description
        == "Technology sector including software and hardware companies"
    )


def test_create_sector_without_description(mock_organization, mock_tlp_marking):
    """Test _create_sector method when description is None."""
    # GIVEN: A mapper instance and a TargetedIndustry object
    # with industry_group populated but description set to None
    report = GTIReportDataFactory.build()
    mapper = _given_gti_report_sector_mapper(
        report, mock_organization, mock_tlp_marking
    )

    industry_data = TargetedIndustryFactory.build(
        industry_group="Technology",
        description=None,
    )

    # WHEN: Creating a sector object through the _create_sector method
    sector = mapper._create_sector(industry_data)

    # THEN: The sector should have the correct name but no description
    # handling None description gracefully without causing errors
    assert sector.name == "Technology"  # noqa: S101
    assert sector.description is None  # noqa: S101


def _given_gti_report_sector_mapper(
    report: GTIReportData, organization: Identity, tlp_marking: MarkingDefinition
) -> GTIReportToSTIXSector:
    """Create a GTIReportToSTIXSector mapper instance."""
    return GTIReportToSTIXSector(
        report=report,
        organization=organization,
        tlp_marking=tlp_marking,
    )


def _when_convert_to_stix(mapper: GTIReportToSTIXSector) -> list[Identity]:
    """Convert GTI report to STIX sectors."""
    return mapper.to_stix()


def _when_convert_to_stix_raises_error(
    mapper: GTIReportToSTIXSector, error_type: type, error_message: str
):
    """Test that conversion raises expected error."""
    with pytest.raises(error_type, match=error_message):
        mapper.to_stix()


def _then_stix_sectors_created_successfully(
    sectors: list[Identity], expected_count: int
):
    """Assert that STIX sectors were created successfully."""
    assert isinstance(sectors, list)  # noqa: S101
    assert len(sectors) == expected_count  # noqa: S101
    for sector in sectors:
        assert hasattr(sector, "name")  # noqa: S101
        assert hasattr(sector, "identity_class")  # noqa: S101
        assert hasattr(sector, "spec_version")  # noqa: S101


def _then_stix_sector_has_correct_properties(
    sector: Identity,
    expected_name: str,
    organization: Identity,
    tlp_marking: MarkingDefinition,
):
    """Assert that STIX sector has correct properties."""
    assert sector.name == expected_name  # noqa: S101
    assert sector.created_by_ref == organization.id  # noqa: S101
    assert tlp_marking.id in sector.object_marking_refs  # noqa: S101
    assert hasattr(sector, "created")  # noqa: S101
    assert hasattr(sector, "modified")  # noqa: S101


def _then_stix_sector_preserves_long_names(sector: Identity):
    """Assert that STIX sector preserves long industry names."""
    assert len(sector.name) == 500  # noqa: S101
    assert sector.name == "A" * 500  # noqa: S101


def _then_stix_sector_preserves_special_characters(sector: Identity):
    """Assert that STIX sector preserves special characters in names."""
    assert sector.name == "Technology & Software"  # noqa: S101
    assert "&" in sector.name  # noqa: S101
