"""Tests for the GTICampaignToSTIXLocation mapper."""

from uuid import uuid4

import pytest
from connector.src.custom.mappers.gti_campaigns.gti_campaign_to_stix_location import (
    GTICampaignToSTIXLocation,
)
from connector.src.custom.models.gti.gti_campaign_model import (
    CampaignModel,
    GTICampaignData,
    SourceRegion,
    TargetedRegion,
)
from polyfactory.factories.pydantic_factory import ModelFactory
from polyfactory.fields import Use
from stix2.v21 import Identity, MarkingDefinition  # type: ignore


class SourceRegionFactory(ModelFactory[SourceRegion]):
    """Factory for SourceRegion model."""

    __model__ = SourceRegion


class TargetedRegionFactory(ModelFactory[TargetedRegion]):
    """Factory for TargetedRegion model."""

    __model__ = TargetedRegion


class CampaignModelFactory(ModelFactory[CampaignModel]):
    """Factory for CampaignModel."""

    __model__ = CampaignModel


class GTICampaignDataFactory(ModelFactory[GTICampaignData]):
    """Factory for GTICampaignData."""

    __model__ = GTICampaignData

    type = "campaign"
    attributes = Use(CampaignModelFactory.build)


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
def campaign_with_country_regions() -> GTICampaignData:
    """Fixture for GTI campaign with country regions."""
    return GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            targeted_regions_hierarchy=[
                TargetedRegionFactory.build(
                    country="United States",
                    country_iso2="US",
                    region="north-america",
                    sub_region="northern-america",
                    description="Primary targeted country",
                )
            ],
            source_regions_hierarchy=[
                SourceRegionFactory.build(
                    country="Russia",
                    country_iso2="RU",
                    region="eastern-europe",
                    sub_region="eastern-europe",
                    description="Primary source country",
                )
            ],
        )
    )


@pytest.fixture
def campaign_with_multiple_countries() -> GTICampaignData:
    """Fixture for GTI campaign with multiple countries."""
    return GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            targeted_regions_hierarchy=[
                TargetedRegionFactory.build(
                    country="United States",
                    country_iso2="US",
                    region="north-america",
                    description="Primary targeted country",
                ),
                TargetedRegionFactory.build(
                    country="Germany",
                    country_iso2="DE",
                    region="western-europe",
                    description="Secondary targeted country",
                ),
                TargetedRegionFactory.build(
                    country="Japan",
                    country_iso2="JP",
                    region="eastern-asia",
                    description="Another targeted country",
                ),
            ],
            source_regions_hierarchy=[
                SourceRegionFactory.build(
                    country="Russia",
                    country_iso2="RU",
                    region="eastern-europe",
                    description="Primary source country",
                ),
                SourceRegionFactory.build(
                    country="China",
                    country_iso2="CN",
                    region="eastern-asia",
                    description="Secondary source country",
                ),
            ],
        )
    )


@pytest.fixture
def campaign_without_regions() -> GTICampaignData:
    """Fixture for GTI campaign without regions."""
    return GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            targeted_regions_hierarchy=None,
            source_regions_hierarchy=None,
        )
    )


@pytest.fixture
def campaign_with_empty_regions() -> GTICampaignData:
    """Fixture for GTI campaign with empty regions."""
    return GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            targeted_regions_hierarchy=[],
            source_regions_hierarchy=[],
        )
    )


@pytest.fixture
def campaign_without_attributes() -> GTICampaignData:
    """Fixture for GTI campaign without attributes."""
    return GTICampaignDataFactory.build(attributes=None)


@pytest.fixture
def campaign_with_region_only() -> GTICampaignData:
    """Fixture for GTI campaign with region only (no country)."""
    return GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            targeted_regions_hierarchy=[
                TargetedRegionFactory.build(
                    country=None,
                    country_iso2=None,
                    region="western-europe",
                    description="Regional target only",
                )
            ],
            source_regions_hierarchy=[
                SourceRegionFactory.build(
                    country=None,
                    country_iso2=None,
                    region="eastern-asia",
                    description="Regional source only",
                )
            ],
        )
    )


@pytest.fixture
def campaign_with_country_without_iso() -> GTICampaignData:
    """Fixture for GTI campaign with country but no ISO code."""
    return GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            targeted_regions_hierarchy=[
                TargetedRegionFactory.build(
                    country="United States",
                    country_iso2=None,
                    region="north-america",
                    description="Country without ISO code",
                )
            ],
            source_regions_hierarchy=[
                SourceRegionFactory.build(
                    country="Russia",
                    country_iso2=None,
                    region="eastern-europe",
                    description="Source country without ISO code",
                )
            ],
        )
    )


@pytest.fixture
def campaign_with_mixed_valid_invalid_countries() -> GTICampaignData:
    """Fixture for GTI campaign with mixed valid and invalid countries."""
    return GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            targeted_regions_hierarchy=[
                TargetedRegionFactory.build(
                    country="United States",
                    country_iso2="US",
                    region="north-america",
                    description="Valid country",
                ),
                TargetedRegionFactory.build(
                    country="Germany",
                    country_iso2=None,
                    region="western-europe",
                    description="Country without ISO code",
                ),
                TargetedRegionFactory.build(
                    country=None,
                    country_iso2="FR",
                    region="western-europe",
                    description="ISO code without country name",
                ),
                TargetedRegionFactory.build(
                    country="Japan",
                    country_iso2="JP",
                    region="eastern-asia",
                    description="Another valid country",
                ),
            ],
            source_regions_hierarchy=[
                SourceRegionFactory.build(
                    country="Russia",
                    country_iso2="RU",
                    region="eastern-europe",
                    description="Valid source country",
                ),
                SourceRegionFactory.build(
                    country="China",
                    country_iso2=None,
                    region="eastern-asia",
                    description="Source country without ISO code",
                ),
            ],
        )
    )


@pytest.fixture
def campaign_with_empty_country_data() -> GTICampaignData:
    """Fixture for GTI campaign with empty country data."""
    return GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            targeted_regions_hierarchy=[
                TargetedRegionFactory.build(
                    country=None,
                    country_iso2=None,
                    region="western-europe",
                    description="No country data",
                )
            ],
            source_regions_hierarchy=[
                SourceRegionFactory.build(
                    country=None,
                    country_iso2=None,
                    region="eastern-asia",
                    description="No source country data",
                )
            ],
        )
    )


@pytest.mark.order(1)
def test_gti_campaign_to_stix_location_country_regions(
    campaign_with_country_regions, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI campaign with country regions to STIX locations."""
    # GIVEN: A GTI campaign containing both targeted and source countries
    # with valid country names and ISO codes for location creation
    mapper = _given_gti_campaign_location_mapper(
        campaign_with_country_regions, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI campaign data to STIX location objects
    locations = _when_convert_to_stix(mapper)

    # THEN: STIX Location objects should be created successfully
    # with both targeted and source countries represented as separate locations
    _then_stix_locations_created_successfully(locations)
    assert len(locations) == 2  # noqa: S101
    _then_stix_location_has_correct_properties(locations[0], mock_organization)
    _then_stix_location_has_correct_country_properties(locations[0], "United States")
    _then_stix_location_has_correct_country_properties(locations[1], "Russia")


@pytest.mark.order(1)
def test_gti_campaign_to_stix_location_multiple_countries(
    campaign_with_multiple_countries, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI campaign with multiple countries."""
    # GIVEN: A GTI campaign containing multiple targeted and source countries
    # with valid country names and ISO codes for location creation
    mapper = _given_gti_campaign_location_mapper(
        campaign_with_multiple_countries, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI campaign data to STIX location objects
    locations = _when_convert_to_stix(mapper)

    # THEN: STIX Location objects should be created for all valid countries
    # with proper country-based locations only
    _then_stix_locations_created_successfully(locations)
    assert len(locations) == 5  # noqa: S101  # 3 targeted + 2 source countries
    _then_stix_location_has_correct_properties(locations[0], mock_organization)

    # Verify all expected countries are present
    country_names = [location.name for location in locations]
    assert "United States" in country_names  # noqa: S101
    assert "Germany" in country_names  # noqa: S101
    assert "Japan" in country_names  # noqa: S101
    assert "Russia" in country_names  # noqa: S101
    assert "China" in country_names  # noqa: S101


@pytest.mark.order(1)
def test_gti_campaign_to_stix_location_without_regions(
    campaign_without_regions, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI campaign without regions."""
    # GIVEN: A GTI campaign with no targeted or source regions defined
    # indicating no geographical targeting or origin information is available
    mapper = _given_gti_campaign_location_mapper(
        campaign_without_regions, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI campaign data to STIX location objects
    locations = _when_convert_to_stix(mapper)

    # THEN: An empty list should be returned
    # since no country information is available to convert
    assert isinstance(locations, list)  # noqa: S101
    assert len(locations) == 0  # noqa: S101


@pytest.mark.order(1)
def test_gti_campaign_to_stix_location_empty_regions(
    campaign_with_empty_regions, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI campaign with empty regions."""
    # GIVEN: A GTI campaign with empty lists for targeted and source regions
    # representing a case where region fields exist but contain no data
    mapper = _given_gti_campaign_location_mapper(
        campaign_with_empty_regions, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI campaign data to STIX location objects
    locations = _when_convert_to_stix(mapper)

    # THEN: An empty list should be returned
    # since empty region lists provide no country information
    assert isinstance(locations, list)  # noqa: S101
    assert len(locations) == 0  # noqa: S101


@pytest.mark.order(1)
def test_gti_campaign_to_stix_location_without_attributes(
    campaign_without_attributes, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI campaign without attributes returns empty list."""
    # GIVEN: A GTI campaign with attributes field set to None
    # making it impossible to access any campaign data including regions
    mapper = _given_gti_campaign_location_mapper(
        campaign_without_attributes, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI campaign data to STIX location objects
    locations = _when_convert_to_stix(mapper)

    # THEN: An empty list should be returned
    # since no attributes are available to process
    assert isinstance(locations, list)  # noqa: S101
    assert len(locations) == 0  # noqa: S101


@pytest.mark.order(1)
def test_gti_campaign_to_stix_location_region_only(
    campaign_with_region_only, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI campaign with region only (no countries)."""
    # GIVEN: A GTI campaign containing only region-level data
    # without specific country information (should be ignored)
    mapper = _given_gti_campaign_location_mapper(
        campaign_with_region_only, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI campaign data to STIX location objects
    locations = _when_convert_to_stix(mapper)

    # THEN: No locations should be created since only countries are processed
    # and regions are ignored according to the requirements
    assert isinstance(locations, list)  # noqa: S101
    assert len(locations) == 0  # noqa: S101


@pytest.mark.order(1)
def test_gti_campaign_to_stix_location_country_without_iso(
    campaign_with_country_without_iso, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI campaign with country without ISO code."""
    # GIVEN: A GTI campaign containing country names but missing ISO codes
    # which are required for proper STIX country location creation
    mapper = _given_gti_campaign_location_mapper(
        campaign_with_country_without_iso, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI campaign data to STIX location objects
    locations = _when_convert_to_stix(mapper)

    # THEN: Countries without ISO codes should be skipped
    # since both country name and ISO code are required
    assert isinstance(locations, list)  # noqa: S101
    assert len(locations) == 0  # noqa: S101


@pytest.mark.order(1)
def test_gti_campaign_to_stix_location_mixed_valid_invalid_countries(
    campaign_with_mixed_valid_invalid_countries, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI campaign with mixed valid and invalid countries."""
    # GIVEN: A GTI campaign containing both valid and invalid country data
    # to test selective processing of only valid geographical information
    mapper = _given_gti_campaign_location_mapper(
        campaign_with_mixed_valid_invalid_countries,
        mock_organization,
        mock_tlp_marking,
    )

    # WHEN: Converting the GTI campaign data to STIX location objects
    locations = _when_convert_to_stix(mapper)

    # THEN: Only valid countries should be processed into STIX Location objects
    # while invalid countries are skipped without affecting valid ones
    _then_stix_locations_created_successfully(locations)
    assert len(locations) == 3  # noqa: S101  # 2 valid targeted + 1 valid source

    # Verify only valid countries are present
    country_names = [location.name for location in locations]
    assert "United States" in country_names  # noqa: S101
    assert "Japan" in country_names  # noqa: S101
    assert "Russia" in country_names  # noqa: S101


@pytest.mark.order(1)
def test_gti_campaign_to_stix_location_empty_country_data(
    campaign_with_empty_country_data, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI campaign with empty country data."""
    # GIVEN: A GTI campaign containing region entries with no country data
    # representing cases where only region/sub-region information is available
    mapper = _given_gti_campaign_location_mapper(
        campaign_with_empty_country_data, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI campaign data to STIX location objects
    locations = _when_convert_to_stix(mapper)

    # THEN: No locations should be created from empty country data
    # since only countries are processed and regions are ignored
    assert isinstance(locations, list)  # noqa: S101
    assert len(locations) == 0  # noqa: S101


@pytest.mark.order(1)
def test_create_country_from_targeted_with_valid_data(
    campaign_with_country_regions, mock_organization, mock_tlp_marking
):
    """Test creating country from targeted region with valid data."""
    # GIVEN: A GTI campaign location mapper with valid country data
    mapper = _given_gti_campaign_location_mapper(
        campaign_with_country_regions, mock_organization, mock_tlp_marking
    )
    region_data = campaign_with_country_regions.attributes.targeted_regions_hierarchy[0]

    # WHEN: Creating a country location from the targeted region data
    location_with_timing = mapper._create_country_from_targeted_with_timing(region_data)
    location = location_with_timing.location if location_with_timing else None

    # THEN: A valid STIX Location object should be created
    # with proper country name and ISO code properties
    assert location is not None  # noqa: S101
    _then_stix_location_has_correct_country_properties(location, "United States")


@pytest.mark.order(1)
def test_create_country_from_source_with_valid_data(
    campaign_with_country_regions, mock_organization, mock_tlp_marking
):
    """Test creating country from source region with valid data."""
    # GIVEN: A GTI campaign location mapper with valid source country data
    mapper = _given_gti_campaign_location_mapper(
        campaign_with_country_regions, mock_organization, mock_tlp_marking
    )
    region_data = campaign_with_country_regions.attributes.source_regions_hierarchy[0]

    # WHEN: Creating a country location from the source region data
    location_with_timing = mapper._create_country_from_source_with_timing(region_data)
    location = location_with_timing.location if location_with_timing else None

    # THEN: A valid STIX Location object should be created
    # with proper country name and ISO code properties
    assert location is not None  # noqa: S101
    _then_stix_location_has_correct_country_properties(location, "Russia")


@pytest.mark.order(1)
def test_create_country_without_country_name(mock_organization, mock_tlp_marking):
    """Test creating country without country name."""
    # GIVEN: A GTI campaign location mapper and region data without country name
    campaign = GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            targeted_regions_hierarchy=[
                TargetedRegionFactory.build(
                    country=None,
                    country_iso2="US",
                    region="north-america",
                )
            ]
        )
    )
    mapper = _given_gti_campaign_location_mapper(
        campaign, mock_organization, mock_tlp_marking
    )
    region_data = campaign.attributes.targeted_regions_hierarchy[0]

    # WHEN: Creating a country location without country name
    location_with_timing = mapper._create_country_from_targeted_with_timing(region_data)
    location = location_with_timing.location if location_with_timing else None

    # THEN: No location should be created
    assert location is None  # noqa: S101


@pytest.mark.order(1)
def test_create_country_without_iso_code(mock_organization, mock_tlp_marking):
    """Test creating country without ISO code."""
    # GIVEN: A GTI campaign location mapper and region data without ISO code
    campaign = GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            targeted_regions_hierarchy=[
                TargetedRegionFactory.build(
                    country="United States",
                    country_iso2=None,
                    region="north-america",
                )
            ]
        )
    )
    mapper = _given_gti_campaign_location_mapper(
        campaign, mock_organization, mock_tlp_marking
    )
    region_data = campaign.attributes.targeted_regions_hierarchy[0]

    # WHEN: Creating a country location without ISO code
    location_with_timing = mapper._create_country_from_targeted_with_timing(region_data)
    location = location_with_timing.location if location_with_timing else None

    # THEN: No location should be created
    assert location is None  # noqa: S101


@pytest.mark.order(1)
def test_gti_campaign_location_mapper_initialization(
    campaign_with_country_regions, mock_organization, mock_tlp_marking
):
    """Test GTICampaignToSTIXLocation mapper initialization."""
    # GIVEN: Valid GTI campaign data, organization, and TLP marking objects
    # for initializing the mapper with all required dependencies
    # WHEN: Creating a new GTICampaignToSTIXLocation mapper instance
    mapper = GTICampaignToSTIXLocation(
        campaign=campaign_with_country_regions,
        organization=mock_organization,
        tlp_marking=mock_tlp_marking,
    )

    # THEN: The mapper should be initialized correctly
    # with all provided objects properly assigned to instance attributes
    assert mapper.campaign == campaign_with_country_regions  # noqa: S101
    assert mapper.organization == mock_organization  # noqa: S101
    assert mapper.tlp_marking == mock_tlp_marking  # noqa: S101


def _given_gti_campaign_location_mapper(
    campaign: GTICampaignData,
    organization: Identity,
    tlp_marking: MarkingDefinition,
) -> GTICampaignToSTIXLocation:
    """Create a GTICampaignToSTIXLocation mapper instance."""
    return GTICampaignToSTIXLocation(
        campaign=campaign,
        organization=organization,
        tlp_marking=tlp_marking,
    )


def _when_convert_to_stix(mapper: GTICampaignToSTIXLocation) -> list:
    """Convert GTI campaign to STIX locations."""
    return mapper.to_stix()


def _then_stix_locations_created_successfully(locations: list):
    """Assert that STIX locations were created successfully."""
    assert isinstance(locations, list)  # noqa: S101
    assert len(locations) > 0  # noqa: S101
    for location in locations:
        assert hasattr(location, "name")  # noqa: S101
        assert hasattr(location, "type")  # noqa: S101
        assert hasattr(location, "spec_version")  # noqa: S101
        assert hasattr(location, "created")  # noqa: S101
        assert hasattr(location, "modified")  # noqa: S101


def _then_stix_location_has_correct_properties(location, organization: Identity):
    """Assert that STIX location has correct properties."""
    assert location.created_by_ref == organization.id  # noqa: S101
    assert location.spec_version == "2.1"  # noqa: S101
    assert location.type == "location"  # noqa: S101


def _then_stix_location_has_correct_country_properties(location, expected_country: str):
    """Assert that STIX location has correct country properties."""
    assert location.name == expected_country  # noqa: S101
    assert hasattr(location, "country")  # noqa: S101
