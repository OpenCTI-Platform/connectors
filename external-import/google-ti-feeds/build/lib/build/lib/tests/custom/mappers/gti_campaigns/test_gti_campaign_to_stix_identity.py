"""Tests for the GTICampaignToSTIXIdentity mapper."""

from uuid import uuid4

import pytest
from connector.src.custom.mappers.gti_campaigns.gti_campaign_to_stix_identity import (
    GTICampaignToSTIXIdentity,
)
from connector.src.custom.models.gti.gti_campaign_model import (
    CampaignModel,
    GTICampaignData,
    TargetedIndustry,
)
from polyfactory.factories.pydantic_factory import ModelFactory
from polyfactory.fields import Use
from stix2.v21 import Identity, MarkingDefinition  # type: ignore


class TargetedIndustryFactory(ModelFactory[TargetedIndustry]):
    """Factory for TargetedIndustry model."""

    __model__ = TargetedIndustry


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
def campaign_with_industries() -> GTICampaignData:
    """Fixture for GTI campaign with targeted industries."""
    return GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            targeted_industries_tree=[
                TargetedIndustryFactory.build(
                    industry_group="Financial Services",
                    industry="Banking",
                    description="Primary target industry",
                    confidence="high",
                ),
                TargetedIndustryFactory.build(
                    industry_group="Technology",
                    industry="Software",
                    description="Secondary target industry",
                    confidence="medium",
                ),
            ]
        )
    )


@pytest.fixture
def campaign_with_multiple_industries() -> GTICampaignData:
    """Fixture for GTI campaign with multiple targeted industries."""
    return GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            targeted_industries_tree=[
                TargetedIndustryFactory.build(
                    industry_group="Financial Services",
                    industry="Banking",
                    description="Banking sector",
                    confidence="high",
                ),
                TargetedIndustryFactory.build(
                    industry_group="Healthcare",
                    industry="Hospitals",
                    description="Healthcare sector",
                    confidence="medium",
                ),
                TargetedIndustryFactory.build(
                    industry_group="Government",
                    industry="Federal",
                    description="Government sector",
                    confidence="high",
                ),
                TargetedIndustryFactory.build(
                    industry_group="Technology",
                    industry="Cloud Services",
                    description="Technology sector",
                    confidence="low",
                ),
            ]
        )
    )


@pytest.fixture
def campaign_without_industries() -> GTICampaignData:
    """Fixture for GTI campaign without targeted industries."""
    return GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(targeted_industries_tree=None)
    )


@pytest.fixture
def campaign_with_empty_industries() -> GTICampaignData:
    """Fixture for GTI campaign with empty industries list."""
    return GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(targeted_industries_tree=[])
    )


@pytest.fixture
def campaign_without_attributes() -> GTICampaignData:
    """Fixture for GTI campaign without attributes."""
    return GTICampaignDataFactory.build(attributes=None)


@pytest.fixture
def campaign_with_industry_without_name() -> GTICampaignData:
    """Fixture for GTI campaign with empty industry name."""
    return GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            targeted_industries_tree=[
                TargetedIndustryFactory.build(
                    industry_group="Financial Services",
                    industry="",
                    description="Industry with empty name",
                    confidence="high",
                )
            ]
        )
    )


@pytest.fixture
def campaign_with_empty_industry_data() -> GTICampaignData:
    """Fixture for GTI campaign with empty industry data."""
    return GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            targeted_industries_tree=[
                TargetedIndustryFactory.build(
                    industry_group="",
                    industry="",
                    description="Empty industry data",
                    confidence="high",
                )
            ]
        )
    )


@pytest.fixture
def campaign_with_empty_industry_group() -> GTICampaignData:
    """Fixture for GTI campaign with empty industry_group but valid industry."""
    return GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            targeted_industries_tree=[
                TargetedIndustryFactory.build(
                    industry_group="",
                    industry="Software Development",
                    description="Industry with empty group but valid industry",
                    confidence="high",
                )
            ]
        )
    )


@pytest.fixture
def campaign_with_long_industry_name() -> GTICampaignData:
    """Fixture for GTI campaign with very long industry name."""
    return GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            targeted_industries_tree=[
                TargetedIndustryFactory.build(
                    industry_group="A" * 500,
                    industry="",
                    description="Very long industry group name",
                    confidence="high",
                )
            ]
        )
    )


@pytest.fixture
def campaign_with_special_characters_in_industry() -> GTICampaignData:
    """Fixture for GTI campaign with special characters in industry name."""
    return GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            targeted_industries_tree=[
                TargetedIndustryFactory.build(
                    industry_group="Financial Services & Banking",
                    industry="Investment Banking & Securities",
                    description="Industry with special characters",
                    confidence="high",
                )
            ]
        )
    )


@pytest.fixture
def campaign_with_mixed_valid_invalid_industries() -> GTICampaignData:
    """Fixture for GTI campaign with mixed valid and invalid industries."""
    return GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            targeted_industries_tree=[
                TargetedIndustryFactory.build(
                    industry_group="Financial Services",
                    industry="Banking",
                    description="Valid industry",
                    confidence="high",
                ),
                TargetedIndustryFactory.build(
                    industry_group="",
                    industry="",
                    description="Invalid industry with empty data",
                    confidence="medium",
                ),
                TargetedIndustryFactory.build(
                    industry_group="Healthcare",
                    industry="Hospitals",
                    description="Another valid industry",
                    confidence="high",
                ),
                TargetedIndustryFactory.build(
                    industry_group="   ",
                    industry="   ",
                    description="Invalid industry with whitespace-only data",
                    confidence="low",
                ),
            ]
        )
    )


@pytest.mark.order(1)
def test_gti_campaign_to_stix_identity_with_industries(
    campaign_with_industries, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI campaign with industries to STIX identity sectors."""
    # GIVEN: A GTI campaign containing targeted industries information
    # with valid industry data for sector identity creation
    mapper = _given_gti_campaign_identity_mapper(
        campaign_with_industries, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI campaign data to STIX identity objects
    identities = _when_convert_to_stix(mapper)

    # THEN: STIX Identity objects should be created successfully
    # with one identity per industry
    _then_stix_identities_created_successfully(identities)
    assert len(identities) == 2  # noqa: S101
    _then_stix_identity_has_correct_properties(identities[0], mock_organization)
    _then_stix_identity_has_correct_sector_properties(
        identities[0], "Financial Services"
    )
    _then_stix_identity_has_correct_sector_properties(identities[1], "Technology")


@pytest.mark.order(1)
def test_gti_campaign_to_stix_identity_with_multiple_industries(
    campaign_with_multiple_industries, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI campaign with multiple industries."""
    # GIVEN: A GTI campaign containing multiple targeted industries
    # with different industry groups and confidence levels
    mapper = _given_gti_campaign_identity_mapper(
        campaign_with_multiple_industries, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI campaign data to STIX identity objects
    identities = _when_convert_to_stix(mapper)

    # THEN: STIX Identity objects should be created for all industries
    # with proper sector classification for each industry
    _then_stix_identities_created_successfully(identities)
    assert len(identities) == 4  # noqa: S101
    _then_stix_identity_has_correct_properties(identities[0], mock_organization)

    # Verify all expected industries are present
    industry_names = [identity.name for identity in identities]
    assert "Financial Services" in industry_names  # noqa: S101
    assert "Healthcare" in industry_names  # noqa: S101
    assert "Government" in industry_names  # noqa: S101
    assert "Technology" in industry_names  # noqa: S101


@pytest.mark.order(1)
def test_gti_campaign_to_stix_identity_without_industries(
    campaign_without_industries, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI campaign without industries."""
    # GIVEN: A GTI campaign with no targeted industries defined
    # indicating no specific industry targeting information is available
    mapper = _given_gti_campaign_identity_mapper(
        campaign_without_industries, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI campaign data to STIX identity objects
    identities = _when_convert_to_stix(mapper)

    # THEN: An empty list should be returned
    # since no industry information is available to convert
    assert isinstance(identities, list)  # noqa: S101
    assert len(identities) == 0  # noqa: S101


@pytest.mark.order(1)
def test_gti_campaign_to_stix_identity_with_empty_industries(
    campaign_with_empty_industries, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI campaign with empty industries list."""
    # GIVEN: A GTI campaign with empty list for targeted industries
    # representing a case where industry fields exist but contain no data
    mapper = _given_gti_campaign_identity_mapper(
        campaign_with_empty_industries, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI campaign data to STIX identity objects
    identities = _when_convert_to_stix(mapper)

    # THEN: An empty list should be returned
    # since empty industry lists provide no sector information
    assert isinstance(identities, list)  # noqa: S101
    assert len(identities) == 0  # noqa: S101


@pytest.mark.order(1)
def test_gti_campaign_to_stix_identity_without_attributes(
    campaign_without_attributes, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI campaign without attributes raises ValueError."""
    # GIVEN: A GTI campaign with attributes field set to None
    # making it impossible to access any campaign data including industries
    mapper = _given_gti_campaign_identity_mapper(
        campaign_without_attributes, mock_organization, mock_tlp_marking
    )

    # WHEN: Attempting to convert the GTI campaign data to STIX identity objects
    # THEN: A ValueError should be raised with message about invalid attributes
    _when_convert_to_stix_raises_error(
        mapper, ValueError, "Invalid campaign attributes"
    )


@pytest.mark.order(1)
def test_gti_campaign_to_stix_identity_with_industry_without_name(
    campaign_with_industry_without_name, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI campaign with empty industry name."""
    # GIVEN: A GTI campaign containing industry data with empty industry name
    # but valid industry group for identity creation
    mapper = _given_gti_campaign_identity_mapper(
        campaign_with_industry_without_name, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI campaign data to STIX identity objects
    identities = _when_convert_to_stix(mapper)

    # THEN: Identity should be created using industry group as fallback
    # since industry group is available when industry name is empty
    _then_stix_identities_created_successfully(identities)
    assert len(identities) == 1  # noqa: S101
    _then_stix_identity_has_correct_sector_properties(
        identities[0], "Financial Services"
    )


@pytest.mark.order(1)
def test_gti_campaign_to_stix_identity_with_empty_industry_data(
    campaign_with_empty_industry_data, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI campaign with empty industry data."""
    # GIVEN: A GTI campaign containing industry entry with no valid data
    # representing malformed industry data with missing information
    mapper = _given_gti_campaign_identity_mapper(
        campaign_with_empty_industry_data, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI campaign data to STIX identity objects
    identities = _when_convert_to_stix(mapper)

    # THEN: No identities should be created since both fields are empty
    # as both industry and industry_group are required for meaningful sectors
    assert isinstance(identities, list)  # noqa: S101
    assert len(identities) == 0  # noqa: S101


@pytest.mark.order(1)
def test_gti_campaign_to_stix_identity_with_empty_industry_group(
    campaign_with_empty_industry_group, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI campaign with empty industry_group but valid industry."""
    # GIVEN: A GTI campaign containing industry data with empty industry_group
    # but valid industry field for identity creation
    mapper = _given_gti_campaign_identity_mapper(
        campaign_with_empty_industry_group, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI campaign data to STIX identity objects
    identities = _when_convert_to_stix(mapper)

    # THEN: Identity should be created since industry field is valid
    # even though industry_group is empty, but the sector name will be empty
    # since the mapper uses industry_group for sector naming
    _then_stix_identities_created_successfully(identities)
    assert len(identities) == 1  # noqa: S101
    assert identities[0].name == "" or identities[0].name is None  # noqa: S101


@pytest.mark.order(1)
def test_gti_campaign_to_stix_identity_with_long_industry_name(
    campaign_with_long_industry_name, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI campaign with very long industry name."""
    # GIVEN: A GTI campaign containing extremely long industry group name
    # to test boundary conditions and ensure long names are handled properly
    mapper = _given_gti_campaign_identity_mapper(
        campaign_with_long_industry_name, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI campaign data to STIX identity objects
    identities = _when_convert_to_stix(mapper)

    # THEN: STIX Identity object should be created successfully
    # preserving the full length of the industry name without truncation
    _then_stix_identities_created_successfully(identities)
    assert len(identities) == 1  # noqa: S101
    _then_stix_identity_preserves_long_industry_name(identities[0])


@pytest.mark.order(1)
def test_gti_campaign_to_stix_identity_with_special_characters(
    campaign_with_special_characters_in_industry,
    mock_organization,
    mock_tlp_marking,
):
    """Test conversion of GTI campaign with special characters in industry name."""
    # GIVEN: A GTI campaign containing industry names with special characters
    # (ampersands, spaces) to test character encoding and preservation
    mapper = _given_gti_campaign_identity_mapper(
        campaign_with_special_characters_in_industry,
        mock_organization,
        mock_tlp_marking,
    )

    # WHEN: Converting the GTI campaign data to STIX identity objects
    identities = _when_convert_to_stix(mapper)

    # THEN: STIX Identity object should be created successfully
    # preserving all special characters in the industry name without modification
    _then_stix_identities_created_successfully(identities)
    assert len(identities) == 1  # noqa: S101
    _then_stix_identity_preserves_special_characters(identities[0])


@pytest.mark.order(1)
def test_gti_campaign_to_stix_identity_with_mixed_valid_invalid_industries(
    campaign_with_mixed_valid_invalid_industries,
    mock_organization,
    mock_tlp_marking,
):
    """Test conversion of GTI campaign with mixed valid and invalid industries."""
    # GIVEN: A GTI campaign containing both valid and invalid industry data
    # to test selective processing of only valid industry information
    mapper = _given_gti_campaign_identity_mapper(
        campaign_with_mixed_valid_invalid_industries,
        mock_organization,
        mock_tlp_marking,
    )

    # WHEN: Converting the GTI campaign data to STIX identity objects
    identities = _when_convert_to_stix(mapper)

    # THEN: Only valid industries should be processed into STIX Identity objects
    # while invalid industries are skipped without affecting valid ones
    _then_stix_identities_created_successfully(identities)
    assert len(identities) == 2  # noqa: S101  # Only valid industries

    # Verify only valid industries are present
    industry_names = [identity.name for identity in identities]
    assert "Financial Services" in industry_names  # noqa: S101
    assert "Healthcare" in industry_names  # noqa: S101


@pytest.mark.order(1)
def test_process_industry_with_valid_data(
    campaign_with_industries, mock_organization, mock_tlp_marking
):
    """Test processing of industry with valid data."""
    # GIVEN: A GTI campaign identity mapper with valid industry data
    mapper = _given_gti_campaign_identity_mapper(
        campaign_with_industries, mock_organization, mock_tlp_marking
    )
    industry_data = campaign_with_industries.attributes.targeted_industries_tree[0]

    # WHEN: Processing the industry data
    identity = mapper._process_industry(industry_data)

    # THEN: A valid STIX Identity object should be created
    # with proper sector properties mapped from industry data
    assert identity is not None  # noqa: S101
    _then_stix_identity_has_correct_sector_properties(identity, "Financial Services")


@pytest.mark.order(1)
def test_process_industry_without_industry_data(mock_organization, mock_tlp_marking):
    """Test processing of industry with empty industry data."""
    # GIVEN: A GTI campaign identity mapper and industry data without valid fields
    campaign = GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            targeted_industries_tree=[
                TargetedIndustryFactory.build(
                    industry_group="",
                    industry="",
                    description="Industry with empty data",
                )
            ]
        )
    )
    mapper = _given_gti_campaign_identity_mapper(
        campaign, mock_organization, mock_tlp_marking
    )
    industry_data = campaign.attributes.targeted_industries_tree[0]

    # WHEN: Processing the industry data with empty fields
    identity = mapper._process_industry(industry_data)

    # THEN: No identity should be created
    assert identity is None  # noqa: S101


@pytest.mark.order(1)
def test_create_sector_with_valid_data(
    campaign_with_industries, mock_organization, mock_tlp_marking
):
    """Test creating sector with valid industry data."""
    # GIVEN: A GTI campaign identity mapper with valid industry data
    mapper = _given_gti_campaign_identity_mapper(
        campaign_with_industries, mock_organization, mock_tlp_marking
    )
    industry_data = campaign_with_industries.attributes.targeted_industries_tree[0]

    # WHEN: Creating a sector identity from the industry data
    identity = mapper._create_sector(industry_data)

    # THEN: A valid STIX Identity object should be created
    # with proper sector classification and properties
    assert identity is not None  # noqa: S101
    _then_stix_identity_has_correct_sector_properties(identity, "Financial Services")
    _then_stix_identity_has_correct_properties(identity, mock_organization)


@pytest.mark.order(1)
def test_gti_campaign_identity_mapper_initialization(
    campaign_with_industries, mock_organization, mock_tlp_marking
):
    """Test GTICampaignToSTIXIdentity mapper initialization."""
    # GIVEN: Valid GTI campaign data, organization, and TLP marking objects
    # for initializing the mapper with all required dependencies
    # WHEN: Creating a new GTICampaignToSTIXIdentity mapper instance
    mapper = GTICampaignToSTIXIdentity(
        campaign=campaign_with_industries,
        organization=mock_organization,
        tlp_marking=mock_tlp_marking,
    )

    # THEN: The mapper should be initialized correctly
    # with all provided objects properly assigned to instance attributes
    assert mapper.campaign == campaign_with_industries  # noqa: S101
    assert mapper.organization == mock_organization  # noqa: S101
    assert mapper.tlp_marking == mock_tlp_marking  # noqa: S101


def _given_gti_campaign_identity_mapper(
    campaign: GTICampaignData,
    organization: Identity,
    tlp_marking: MarkingDefinition,
) -> GTICampaignToSTIXIdentity:
    """Create a GTICampaignToSTIXIdentity mapper instance."""
    return GTICampaignToSTIXIdentity(
        campaign=campaign,
        organization=organization,
        tlp_marking=tlp_marking,
    )


def _when_convert_to_stix(mapper: GTICampaignToSTIXIdentity) -> list:
    """Convert GTI campaign to STIX identities."""
    return mapper.to_stix()


def _when_convert_to_stix_raises_error(
    mapper: GTICampaignToSTIXIdentity, error_type: type, error_message: str
):
    """Test that conversion raises expected error."""
    with pytest.raises(error_type, match=error_message):
        mapper.to_stix()


def _then_stix_identities_created_successfully(identities: list):
    """Assert that STIX identities were created successfully."""
    assert isinstance(identities, list)  # noqa: S101
    assert len(identities) > 0  # noqa: S101
    for identity in identities:
        assert isinstance(identity, Identity)  # noqa: S101
        assert hasattr(identity, "name")  # noqa: S101
        assert hasattr(identity, "identity_class")  # noqa: S101
        assert hasattr(identity, "spec_version")  # noqa: S101
        assert hasattr(identity, "created")  # noqa: S101
        assert hasattr(identity, "modified")  # noqa: S101


def _then_stix_identity_has_correct_properties(
    identity: Identity, organization: Identity
):
    """Assert that STIX identity has correct properties."""
    assert identity.created_by_ref == organization.id  # noqa: S101
    assert identity.identity_class.value == "class"  # noqa: S101
    assert identity.spec_version == "2.1"  # noqa: S101
    assert identity.type == "identity"  # noqa: S101


def _then_stix_identity_has_correct_sector_properties(
    identity: Identity, expected_sector: str
):
    """Assert that STIX identity has correct sector properties."""
    assert identity.name == expected_sector  # noqa: S101


def _then_stix_identity_preserves_long_industry_name(identity: Identity):
    """Assert that STIX identity preserves long industry names."""
    assert len(identity.name) == 500  # noqa: S101
    assert identity.name == "A" * 500  # noqa: S101


def _then_stix_identity_preserves_special_characters(identity: Identity):
    """Assert that STIX identity preserves special characters in industry names."""
    assert "&" in identity.name  # noqa: S101
    assert identity.name == "Financial Services & Banking"  # noqa: S101
