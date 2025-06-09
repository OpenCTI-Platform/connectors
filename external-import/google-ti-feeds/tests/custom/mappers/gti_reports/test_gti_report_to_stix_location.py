"""Tests for the GTIReportToSTIXLocation mapper."""

from uuid import uuid4

import pytest
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_location import (
    GTIReportToSTIXLocation,
)
from connector.src.custom.models.gti_reports.gti_report_model import (
    GTIReportData,
    Links,
    ReportModel,
    TargetedRegion,
)
from polyfactory.factories.pydantic_factory import ModelFactory
from polyfactory.fields import Use
from stix2.v21 import Identity, Location, MarkingDefinition  # type: ignore


class LinksFactory(ModelFactory[Links]):
    """Factory for Links model."""

    __model__ = Links


class TargetedRegionFactory(ModelFactory[TargetedRegion]):
    """Factory for TargetedRegion model."""

    __model__ = TargetedRegion


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
def report_with_country_region() -> GTIReportData:
    """Fixture for GTI report with country-based targeted region."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            targeted_regions_hierarchy=[
                TargetedRegionFactory.build(
                    country="United States",
                    country_iso2="US",
                    region="northern-america",
                    sub_region=None,
                )
            ]
        )
    )


@pytest.fixture
def report_with_multiple_regions() -> GTIReportData:
    """Fixture for GTI report with multiple targeted regions."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            targeted_regions_hierarchy=[
                TargetedRegionFactory.build(
                    country="France",
                    country_iso2="FR",
                    region="europe",
                    sub_region="western-europe",
                ),
                TargetedRegionFactory.build(
                    country="Japan",
                    country_iso2="JP",
                    region="asia",
                    sub_region="eastern-asia",
                ),
                TargetedRegionFactory.build(
                    country=None,
                    country_iso2=None,
                    region="africa",
                    sub_region=None,
                ),
            ]
        )
    )


@pytest.fixture
def report_without_regions() -> GTIReportData:
    """Fixture for GTI report without targeted regions."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(targeted_regions_hierarchy=None)
    )


@pytest.fixture
def report_with_empty_regions() -> GTIReportData:
    """Fixture for GTI report with empty targeted regions list."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(targeted_regions_hierarchy=[])
    )


@pytest.fixture
def report_without_attributes() -> GTIReportData:
    """Fixture for GTI report without attributes."""
    return GTIReportDataFactory.build(attributes=None)


@pytest.fixture
def report_with_region_only() -> GTIReportData:
    """Fixture for GTI report with region-only targeted region."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            targeted_regions_hierarchy=[
                TargetedRegionFactory.build(
                    country=None,
                    country_iso2=None,
                    region="europe",
                    sub_region=None,
                )
            ]
        )
    )


@pytest.fixture
def report_with_sub_region_only() -> GTIReportData:
    """Fixture for GTI report with sub-region-only targeted region."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            targeted_regions_hierarchy=[
                TargetedRegionFactory.build(
                    country=None,
                    country_iso2=None,
                    region=None,
                    sub_region="western-europe",
                )
            ]
        )
    )


@pytest.fixture
def report_with_country_without_iso() -> GTIReportData:
    """Fixture for GTI report with country missing ISO code."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            targeted_regions_hierarchy=[
                TargetedRegionFactory.build(
                    country="United States",
                    country_iso2=None,
                    region="northern-america",
                    sub_region=None,
                )
            ]
        )
    )


@pytest.fixture
def report_with_invalid_region() -> GTIReportData:
    """Fixture for GTI report with invalid region name."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            targeted_regions_hierarchy=[
                TargetedRegionFactory.build(
                    country=None,
                    country_iso2=None,
                    region="invalid-region-name",
                    sub_region=None,
                )
            ]
        )
    )


@pytest.fixture
def report_with_mixed_valid_invalid_regions() -> GTIReportData:
    """Fixture for GTI report with mix of valid and invalid regions."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            targeted_regions_hierarchy=[
                TargetedRegionFactory.build(
                    country="Germany",
                    country_iso2="DE",
                    region="europe",
                    sub_region="western-europe",
                ),
                TargetedRegionFactory.build(
                    country="Invalid Country",
                    country_iso2=None,
                    region="invalid-region",
                    sub_region=None,
                ),
                TargetedRegionFactory.build(
                    country=None,
                    country_iso2=None,
                    region="asia",
                    sub_region=None,
                ),
            ]
        )
    )


@pytest.fixture
def report_with_empty_region_data() -> GTIReportData:
    """Fixture for GTI report with empty region data."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            targeted_regions_hierarchy=[
                TargetedRegionFactory.build(
                    country=None,
                    country_iso2=None,
                    region=None,
                    sub_region=None,
                )
            ]
        )
    )


def test_gti_report_to_stix_location_country_region(
    report_with_country_region, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report with country-based targeted region to STIX location."""
    # GIVEN: A GTI report containing a single targeted region with complete country information
    # including country name (United States), ISO2 code (US), and regional classification (northern-america)
    mapper = _given_gti_report_location_mapper(
        report_with_country_region, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report data to STIX location objects
    locations = _when_convert_to_stix(mapper)

    # THEN: Exactly one STIX Location object should be created
    # with correct country properties and STIX metadata
    _then_stix_locations_created_successfully(locations, 1)
    _then_stix_location_has_correct_country_properties(
        locations[0], mock_organization, mock_tlp_marking
    )


def test_gti_report_to_stix_location_multiple_regions(
    report_with_multiple_regions, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report with multiple targeted regions to STIX locations."""
    # GIVEN: A GTI report containing three diverse targeted regions:
    # France (complete country data), Japan (complete country data), and Africa (region-only data)
    # representing different types of geographical targeting information
    mapper = _given_gti_report_location_mapper(
        report_with_multiple_regions, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report data to STIX location objects
    locations = _when_convert_to_stix(mapper)

    # THEN: Three STIX Location objects should be created, one for each targeted region
    # maintaining proper STIX properties and organization/TLP marking references
    _then_stix_locations_created_successfully(locations, 3)
    for location in locations:
        _then_stix_location_has_correct_properties(
            location, mock_organization, mock_tlp_marking
        )


def test_gti_report_to_stix_location_without_regions(
    report_without_regions, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report without targeted regions."""
    # GIVEN: A GTI report with targeted_regions_hierarchy set to None
    # indicating no geographical targeting information is available
    mapper = _given_gti_report_location_mapper(
        report_without_regions, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report data to STIX location objects
    locations = _when_convert_to_stix(mapper)

    # THEN: No STIX Location objects should be created
    # since there are no regions to process
    _then_stix_locations_created_successfully(locations, 0)


def test_gti_report_to_stix_location_empty_regions(
    report_with_empty_regions, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report with empty targeted regions list."""
    # GIVEN: A GTI report with targeted_regions_hierarchy set to an empty list
    # indicating that geographical targeting was considered but no specific regions were identified
    mapper = _given_gti_report_location_mapper(
        report_with_empty_regions, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report data to STIX location objects
    locations = _when_convert_to_stix(mapper)

    # THEN: No STIX Location objects should be created
    # since the empty list contains no regions to process
    _then_stix_locations_created_successfully(locations, 0)


def test_gti_report_to_stix_location_without_attributes(
    report_without_attributes, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report without attributes raises ValueError."""
    # GIVEN: A GTI report with attributes field set to None
    # making it impossible to access any report data including geographical targeting information
    mapper = _given_gti_report_location_mapper(
        report_without_attributes, mock_organization, mock_tlp_marking
    )

    # WHEN: Attempting to convert the GTI report data to STIX location objects
    # THEN: A ValueError should be raised with message about invalid attributes
    # since the mapper cannot process a report without proper attribute structure
    _when_convert_to_stix_raises_error(mapper, ValueError, "Invalid report attributes")


def test_gti_report_to_stix_location_region_only(
    report_with_region_only, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report with region-only targeted region."""
    # GIVEN: A GTI report containing a targeted region with only regional classification (europe)
    # but no specific country or sub-region information, representing broad geographical targeting
    mapper = _given_gti_report_location_mapper(
        report_with_region_only, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report data to STIX location objects
    locations = _when_convert_to_stix(mapper)

    # THEN: One STIX Location object should be created successfully
    # with correct region properties instead of country-specific properties
    _then_stix_locations_created_successfully(locations, 1)
    _then_stix_location_has_correct_region_properties(
        locations[0], mock_organization, mock_tlp_marking
    )


def test_gti_report_to_stix_location_sub_region_only(
    report_with_sub_region_only, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report with sub-region-only targeted region."""
    # GIVEN: A GTI report containing a targeted region with only sub-regional classification (western-europe)
    # but no main region or country information, representing specific sub-regional targeting
    mapper = _given_gti_report_location_mapper(
        report_with_sub_region_only, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report data to STIX location objects
    locations = _when_convert_to_stix(mapper)

    # THEN: One STIX Location object should be created successfully
    # treating the sub-region as a regional location with proper STIX properties
    _then_stix_locations_created_successfully(locations, 1)
    _then_stix_location_has_correct_region_properties(
        locations[0], mock_organization, mock_tlp_marking
    )


def test_gti_report_to_stix_location_country_without_iso(
    report_with_country_without_iso, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report with country missing ISO code."""
    # GIVEN: A GTI report containing a targeted region with country name (United States)
    # but missing ISO2 code, representing incomplete country identification data
    mapper = _given_gti_report_location_mapper(
        report_with_country_without_iso, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report data to STIX location objects
    locations = _when_convert_to_stix(mapper)

    # THEN: One STIX Location object should still be created successfully
    # even without ISO code, using available country and region information
    _then_stix_locations_created_successfully(locations, 1)


def test_gti_report_to_stix_location_invalid_region(
    report_with_invalid_region, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report with invalid region name."""
    # GIVEN: A GTI report containing a targeted region with an invalid region name (invalid-region-name)
    # that doesn't match any recognized geographical region classifications
    mapper = _given_gti_report_location_mapper(
        report_with_invalid_region, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report data to STIX location objects
    locations = _when_convert_to_stix(mapper)

    # THEN: No STIX Location objects should be created
    # since invalid region names are filtered out during processing
    _then_stix_locations_created_successfully(locations, 0)


def test_gti_report_to_stix_location_mixed_valid_invalid_regions(
    report_with_mixed_valid_invalid_regions, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report with mix of valid and invalid regions."""
    # GIVEN: A GTI report containing three targeted regions: one valid country (Germany),
    # one invalid country/region combination, and one valid region-only (asia)
    # testing the mapper's ability to filter and process mixed data quality
    mapper = _given_gti_report_location_mapper(
        report_with_mixed_valid_invalid_regions, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report data to STIX location objects
    locations = _when_convert_to_stix(mapper)

    # THEN: Two STIX Location objects should be created for the valid regions
    # while invalid region data is filtered out during processing
    _then_stix_locations_created_successfully(locations, 2)


def test_gti_report_to_stix_location_empty_region_data(
    report_with_empty_region_data, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report with empty region data."""
    # GIVEN: A GTI report containing a targeted region object with all location fields set to None
    # (country, country_iso2, region, sub_region) representing completely empty geographical data
    mapper = _given_gti_report_location_mapper(
        report_with_empty_region_data, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report data to STIX location objects
    locations = _when_convert_to_stix(mapper)

    # THEN: No STIX Location objects should be created
    # since empty region data provides no valid geographical information to process
    _then_stix_locations_created_successfully(locations, 0)


def test_process_region_with_country_data(mock_organization, mock_tlp_marking):
    """Test _process_region method with country data."""
    # GIVEN: A mapper instance and a TargetedRegion object with complete country information
    # including country name (Germany), ISO2 code (DE), and regional classification (europe)
    report = GTIReportDataFactory.build()
    mapper = _given_gti_report_location_mapper(
        report, mock_organization, mock_tlp_marking
    )

    region_data = TargetedRegionFactory.build(
        country="Germany",
        country_iso2="DE",
        region="europe",
    )

    # WHEN: Processing the region data through the _process_region method
    location = mapper._process_region(region_data)

    # THEN: A valid STIX Location object should be returned
    # since the country data provides sufficient information for location creation
    assert location is not None  # noqa: S101


def test_process_region_with_region_only(mock_organization, mock_tlp_marking):
    """Test _process_region method with region-only data."""
    # GIVEN: A mapper instance and a TargetedRegion object with only regional classification (asia)
    # but no country or sub-region information, representing broad geographical targeting
    report = GTIReportDataFactory.build()
    mapper = _given_gti_report_location_mapper(
        report, mock_organization, mock_tlp_marking
    )

    region_data = TargetedRegionFactory.build(
        country=None,
        country_iso2=None,
        region="asia",
        sub_region=None,
    )

    # WHEN: Processing the region data through the _process_region method
    location = mapper._process_region(region_data)

    # THEN: A valid STIX Location object should be returned
    # since region information alone is sufficient for regional location creation
    assert location is not None  # noqa: S101


def test_process_region_with_empty_data(mock_organization, mock_tlp_marking):
    """Test _process_region method with empty region data."""
    # GIVEN: A mapper instance and a TargetedRegion object with all location fields set to None
    # representing completely empty geographical data with no usable location information
    report = GTIReportDataFactory.build()
    mapper = _given_gti_report_location_mapper(
        report, mock_organization, mock_tlp_marking
    )

    region_data = TargetedRegionFactory.build(
        country=None,
        country_iso2=None,
        region=None,
        sub_region=None,
    )

    # WHEN: Processing the empty region data through the _process_region method
    location = mapper._process_region(region_data)

    # THEN: No location object should be returned (None)
    # since empty data provides no valid geographical information for location creation
    assert location is None  # noqa: S101


def test_create_country_with_valid_data(mock_organization, mock_tlp_marking):
    """Test _create_country method with valid country data."""
    # GIVEN: A mapper instance and a TargetedRegion object with complete country identification
    # including both country name (Canada) and ISO2 code (CA) for proper STIX country creation
    report = GTIReportDataFactory.build()
    mapper = _given_gti_report_location_mapper(
        report, mock_organization, mock_tlp_marking
    )

    region_data = TargetedRegionFactory.build(
        country="Canada",
        country_iso2="CA",
    )

    # WHEN: Creating a country location through the _create_country method
    location = mapper._create_country(region_data)

    # THEN: A valid STIX Location object should be returned
    # with proper country properties based on the provided identification data
    assert location is not None  # noqa: S101


def test_create_country_without_country(mock_organization, mock_tlp_marking):
    """Test _create_country method without country data."""
    # GIVEN: A mapper instance and a TargetedRegion object with ISO2 code (CA)
    # but missing country name, representing incomplete country identification data
    report = GTIReportDataFactory.build()
    mapper = _given_gti_report_location_mapper(
        report, mock_organization, mock_tlp_marking
    )

    region_data = TargetedRegionFactory.build(
        country=None,
        country_iso2="CA",
    )

    # WHEN: Attempting to create a country location through the _create_country method
    location = mapper._create_country(region_data)

    # THEN: No location object should be returned (None)
    # since country name is required for proper country location creation
    assert location is None  # noqa: S101


def test_create_country_without_iso_code(mock_organization, mock_tlp_marking):
    """Test _create_country method without ISO code."""
    # GIVEN: A mapper instance and a TargetedRegion object with country name (Canada)
    # but missing ISO2 code, representing partial country identification data
    report = GTIReportDataFactory.build()
    mapper = _given_gti_report_location_mapper(
        report, mock_organization, mock_tlp_marking
    )

    region_data = TargetedRegionFactory.build(
        country="Canada",
        country_iso2=None,
    )

    # WHEN: Attempting to create a country location through the _create_country method
    location = mapper._create_country(region_data)

    # THEN: No location object should be returned (None)
    # since ISO2 code is required for proper STIX country location creation
    assert location is None  # noqa: S101


def test_create_region_with_valid_region(mock_organization, mock_tlp_marking):
    """Test _create_region method with valid region data."""
    # GIVEN: A mapper instance and a TargetedRegion object with valid region classification (europe)
    # and sub-region information, configured to create a main region location
    report = GTIReportDataFactory.build()
    mapper = _given_gti_report_location_mapper(
        report, mock_organization, mock_tlp_marking
    )

    region_data = TargetedRegionFactory.build(
        region="europe",
        sub_region="western-europe",
    )

    # WHEN: Creating a region location through the _create_region method for main region
    location = mapper._create_region(region_data, is_sub_region=False)

    # THEN: A valid STIX Location object should be returned
    # with proper regional properties based on the main region classification
    assert location is not None  # noqa: S101


def test_create_region_with_valid_sub_region(mock_organization, mock_tlp_marking):
    """Test _create_region method with valid sub-region data."""
    # GIVEN: A mapper instance and a TargetedRegion object with valid sub-region classification (western-europe)
    # and parent region information, configured to create a sub-region location
    report = GTIReportDataFactory.build()
    mapper = _given_gti_report_location_mapper(
        report, mock_organization, mock_tlp_marking
    )

    region_data = TargetedRegionFactory.build(
        region="europe",
        sub_region="western-europe",
    )

    # WHEN: Creating a region location through the _create_region method for sub-region
    location = mapper._create_region(region_data, is_sub_region=True)

    # THEN: A valid STIX Location object should be returned
    # with proper regional properties based on the sub-region classification
    assert location is not None  # noqa: S101


def test_create_region_with_invalid_region(mock_organization, mock_tlp_marking):
    """Test _create_region method with invalid region name."""
    # GIVEN: A mapper instance and a TargetedRegion object with an invalid region name (invalid-region)
    # that doesn't match any recognized geographical region classifications
    report = GTIReportDataFactory.build()
    mapper = _given_gti_report_location_mapper(
        report, mock_organization, mock_tlp_marking
    )

    region_data = TargetedRegionFactory.build(
        region="invalid-region",
        sub_region=None,
    )

    # WHEN: Attempting to create a region location through the _create_region method
    location = mapper._create_region(region_data, is_sub_region=False)

    # THEN: No location object should be returned (None)
    # since invalid region names cannot be used to create valid STIX locations
    assert location is None  # noqa: S101


def test_create_region_without_region_name(mock_organization, mock_tlp_marking):
    """Test _create_region method without region name."""
    # GIVEN: A mapper instance and a TargetedRegion object with both region and sub_region set to None
    # representing completely missing regional classification data
    report = GTIReportDataFactory.build()
    mapper = _given_gti_report_location_mapper(
        report, mock_organization, mock_tlp_marking
    )

    region_data = TargetedRegionFactory.build(
        region=None,
        sub_region=None,
    )

    # WHEN: Attempting to create a region location through the _create_region method
    location = mapper._create_region(region_data, is_sub_region=False)

    # THEN: No location object should be returned (None)
    # since region name is required for creating any type of regional STIX location
    assert location is None  # noqa: S101


def _given_gti_report_location_mapper(
    report: GTIReportData, organization: Identity, tlp_marking: MarkingDefinition
) -> GTIReportToSTIXLocation:
    """Create a GTIReportToSTIXLocation mapper instance."""
    return GTIReportToSTIXLocation(
        report=report,
        organization=organization,
        tlp_marking=tlp_marking,
    )


def _when_convert_to_stix(mapper: GTIReportToSTIXLocation) -> list[Location]:
    """Convert GTI report to STIX locations."""
    return mapper.to_stix()


def _when_convert_to_stix_raises_error(
    mapper: GTIReportToSTIXLocation, error_type: type, error_message: str
):
    """Test that conversion raises expected error."""
    with pytest.raises(error_type, match=error_message):
        mapper.to_stix()


def _then_stix_locations_created_successfully(
    locations: list[Location], expected_count: int
):
    """Assert that STIX locations were created successfully."""
    assert isinstance(locations, list)  # noqa: S101
    assert len(locations) == expected_count  # noqa: S101
    for location in locations:
        assert hasattr(location, "name")  # noqa: S101
        assert hasattr(location, "spec_version")  # noqa: S101


def _then_stix_location_has_correct_properties(
    location: Location,
    organization: Identity,
    tlp_marking: MarkingDefinition,
):
    """Assert that STIX location has correct properties."""
    assert hasattr(location, "created_by_ref")  # noqa: S101
    assert hasattr(location, "object_marking_refs")  # noqa: S101
    assert hasattr(location, "created")  # noqa: S101
    assert hasattr(location, "modified")  # noqa: S101


def _then_stix_location_has_correct_country_properties(
    location: Location,
    organization: Identity,
    tlp_marking: MarkingDefinition,
):
    """Assert that STIX location has correct country properties."""
    _then_stix_location_has_correct_properties(location, organization, tlp_marking)
    assert hasattr(location, "country")  # noqa: S101


def _then_stix_location_has_correct_region_properties(
    location: Location,
    organization: Identity,
    tlp_marking: MarkingDefinition,
):
    """Assert that STIX location has correct region properties."""
    _then_stix_location_has_correct_properties(location, organization, tlp_marking)
    assert hasattr(location, "region")  # noqa: S101
