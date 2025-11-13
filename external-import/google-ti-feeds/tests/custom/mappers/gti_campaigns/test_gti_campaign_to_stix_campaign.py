"""Tests for the GTICampaignToSTIXCampaign mapper."""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import pytest
from connector.src.custom.mappers.gti_campaigns.gti_campaign_to_stix_campaign import (
    GTICampaignToSTIXCampaign,
)
from connector.src.custom.models.gti.gti_campaign_model import (
    ActivityDetail,
    AltNameDetail,
    CampaignModel,
    GTICampaignData,
    TagDetail,
)
from polyfactory import Use
from polyfactory.factories.pydantic_factory import ModelFactory
from stix2.v21 import Identity, MarkingDefinition  # type: ignore

# =====================
# Polyfactory Factories
# =====================


class AltNameDetailFactory(ModelFactory[AltNameDetail]):
    """Factory for AltNameDetail model."""

    __model__ = AltNameDetail

    confidence = "high"
    value = "Campaign Example"


class ActivityDetailFactory(ModelFactory[ActivityDetail]):
    """Factory for ActivityDetail model."""

    __model__ = ActivityDetail

    confidence = "high"
    value = "2023-01-01T00:00:00Z"


class TagDetailFactory(ModelFactory[TagDetail]):
    """Factory for TagDetail model."""

    __model__ = TagDetail

    confidence = "high"
    value = "Campaign"


class CampaignModelFactory(ModelFactory[CampaignModel]):
    """Factory for CampaignModel."""

    __model__ = CampaignModel

    name = "Test Campaign"
    creation_date = 1672531200
    last_modification_date = 1672617600
    description = "A test campaign"
    private = False


class GTICampaignDataFactory(ModelFactory[GTICampaignData]):
    """Factory for GTICampaignData."""

    __model__ = GTICampaignData

    type = "campaign"
    attributes = Use(CampaignModelFactory.build)


# =====================
# Fixtures
# =====================


@pytest.fixture
def mock_organization() -> Identity:
    """Fixture for mock organization identity."""
    return Identity(
        id=f"identity--{uuid4()}",
        name="Test Organization",
        identity_class="organization",
    )


@pytest.fixture
def mock_tlp_marking() -> MarkingDefinition:
    """Fixture for mock TLP marking definition."""
    return MarkingDefinition(
        id=f"marking-definition--{uuid4()}",
        definition_type="statement",
        definition={"statement": "Internal Use Only"},
    )


@pytest.fixture
def minimal_campaign_data() -> GTICampaignData:
    """Fixture for minimal campaign data."""
    return GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            alt_names_details=None,
            first_seen_details=None,
            last_seen_details=None,
            tags_details=None,
        )
    )


@pytest.fixture
def campaign_with_seen_dates() -> GTICampaignData:
    """Fixture for campaign data with seen dates."""
    return GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            first_seen_details=[
                ActivityDetailFactory.build(value="2023-01-01T00:00:00Z")
            ],
            last_seen_details=[
                ActivityDetailFactory.build(value="2023-12-31T23:59:59Z")
            ],
        )
    )


@pytest.fixture
def campaign_with_tags() -> GTICampaignData:
    """Fixture for campaign data with tags."""
    return GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            tags_details=[
                TagDetailFactory.build(value="Campaign"),
                TagDetailFactory.build(value="Advanced Persistent Threat"),
            ]
        )
    )


@pytest.fixture
def campaign_with_all_data() -> GTICampaignData:
    """Fixture for campaign data with all optional fields."""
    return GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            first_seen_details=[
                ActivityDetailFactory.build(value="2023-01-01T00:00:00Z")
            ],
            last_seen_details=[
                ActivityDetailFactory.build(value="2023-12-31T23:59:59Z")
            ],
            tags_details=[TagDetailFactory.build(value="Campaign")],
        )
    )


@pytest.fixture
def campaign_without_attributes() -> GTICampaignData:
    """Fixture for campaign data without attributes."""
    return GTICampaignDataFactory.build(attributes=None)


@pytest.fixture
def campaign_with_invalid_dates() -> GTICampaignData:
    """Fixture for campaign data with invalid date formats."""
    return GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            first_seen_details=[
                ActivityDetailFactory.build(value="invalid-date-format")
            ],
            last_seen_details=[
                ActivityDetailFactory.build(value="2023-13-32T25:61:61Z")
            ],
        )
    )


@pytest.fixture
def campaign_with_empty_collections() -> GTICampaignData:
    """Fixture for campaign data with empty collections."""
    return GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            first_seen_details=[],
            last_seen_details=[],
            tags_details=[],
        )
    )


@pytest.fixture
def campaign_with_short_name() -> GTICampaignData:
    """Fixture for campaign data with name too short."""
    return GTICampaignDataFactory.build(attributes=CampaignModelFactory.build(name="X"))


@pytest.fixture
def campaign_with_empty_name() -> GTICampaignData:
    """Fixture for campaign data with empty name."""
    return GTICampaignDataFactory.build(attributes=CampaignModelFactory.build(name=""))


@pytest.fixture
def campaign_with_none_name() -> GTICampaignData:
    """Fixture for campaign data with None name."""
    return GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(name=None)
    )


# =====================
# Test Cases
# =====================


# Scenario: Create STIX campaign with minimal required data
@pytest.mark.order(1)
def test_gti_campaign_to_stix_minimal_data(
    minimal_campaign_data: GTICampaignData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test converting GTI campaign with minimal data to STIX."""
    # Given a GTI campaign with minimal data
    mapper = _given_gti_campaign_mapper(
        minimal_campaign_data, mock_organization, mock_tlp_marking
    )
    # When converting to STIX
    stix_campaign = _when_convert_to_stix(mapper)
    # Then STIX campaign should be created with basic fields
    _then_stix_campaign_created_successfully(
        stix_campaign,
        minimal_campaign_data,
        mock_organization,
        mock_tlp_marking,
    )


# Scenario: Create STIX campaign with seen dates
@pytest.mark.order(1)
def test_gti_campaign_to_stix_with_seen_dates(
    campaign_with_seen_dates: GTICampaignData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test converting GTI campaign with seen dates to STIX."""
    # Given a GTI campaign with seen dates
    mapper = _given_gti_campaign_mapper(
        campaign_with_seen_dates, mock_organization, mock_tlp_marking
    )
    # When converting to STIX
    stix_campaign = _when_convert_to_stix(mapper)
    # Then STIX campaign should include seen dates
    _then_stix_campaign_created_successfully(
        stix_campaign,
        campaign_with_seen_dates,
        mock_organization,
        mock_tlp_marking,
    )
    _then_stix_campaign_has_seen_dates(stix_campaign, campaign_with_seen_dates)


# Scenario: Create STIX campaign with tags/labels
@pytest.mark.order(1)
def test_gti_campaign_to_stix_with_tags(
    campaign_with_tags: GTICampaignData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test converting GTI campaign with tags to STIX."""
    # Given a GTI campaign with tags
    mapper = _given_gti_campaign_mapper(
        campaign_with_tags, mock_organization, mock_tlp_marking
    )
    # When converting to STIX
    stix_campaign = _when_convert_to_stix(mapper)
    # Then STIX campaign should include labels
    _then_stix_campaign_created_successfully(
        stix_campaign,
        campaign_with_tags,
        mock_organization,
        mock_tlp_marking,
    )
    _then_stix_campaign_has_labels(stix_campaign, campaign_with_tags)


# Scenario: Create STIX campaign with all optional data
@pytest.mark.order(1)
def test_gti_campaign_to_stix_with_all_data(
    campaign_with_all_data: GTICampaignData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test converting GTI campaign with all optional data to STIX."""
    # Given a GTI campaign with all optional data
    mapper = _given_gti_campaign_mapper(
        campaign_with_all_data, mock_organization, mock_tlp_marking
    )
    # When converting to STIX
    stix_campaign = _when_convert_to_stix(mapper)
    # Then STIX campaign should include all data
    _then_stix_campaign_created_successfully(
        stix_campaign,
        campaign_with_all_data,
        mock_organization,
        mock_tlp_marking,
    )
    _then_stix_campaign_has_seen_dates(stix_campaign, campaign_with_all_data)
    _then_stix_campaign_has_labels(stix_campaign, campaign_with_all_data)


# =====================
# Edge Cases and Error Scenarios
# =====================


# Scenario: Handle campaign without attributes
@pytest.mark.order(1)
def test_gti_campaign_to_stix_without_attributes(
    campaign_without_attributes: GTICampaignData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test handling GTI campaign without attributes."""
    # Given a GTI campaign without attributes
    mapper = _given_gti_campaign_mapper(
        campaign_without_attributes, mock_organization, mock_tlp_marking
    )
    # When converting to STIX
    # Then should raise ValueError
    _when_convert_to_stix_raises_error(mapper, ValueError, "Invalid GTI campaign data")


# Scenario: Handle None campaign object
@pytest.mark.order(1)
def test_gti_campaign_none_object(
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test handling None campaign object."""
    # Given a None campaign object
    mapper = GTICampaignToSTIXCampaign(None, mock_organization, mock_tlp_marking)
    # When converting to STIX
    # Then should raise ValueError
    _when_convert_to_stix_raises_error(mapper, ValueError, "Invalid GTI campaign data")


# Scenario: Handle campaign with invalid date formats
@pytest.mark.order(1)
def test_gti_campaign_invalid_dates(
    campaign_with_invalid_dates: GTICampaignData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test handling GTI campaign with invalid date formats."""
    # Given a GTI campaign with invalid dates
    mapper = _given_gti_campaign_mapper(
        campaign_with_invalid_dates, mock_organization, mock_tlp_marking
    )
    # When converting to STIX
    stix_campaign = _when_convert_to_stix(mapper)
    # Then should handle invalid dates gracefully
    _then_stix_campaign_handles_invalid_dates(stix_campaign)


# Scenario: Handle campaign with empty collections
@pytest.mark.order(1)
def test_gti_campaign_empty_collections(
    campaign_with_empty_collections: GTICampaignData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test handling GTI campaign with empty collections."""
    # Given a GTI campaign with empty collections
    mapper = _given_gti_campaign_mapper(
        campaign_with_empty_collections, mock_organization, mock_tlp_marking
    )
    # When converting to STIX
    stix_campaign = _when_convert_to_stix(mapper)
    # Then should handle empty collections gracefully
    _then_stix_campaign_handles_empty_collections(stix_campaign)


# Scenario: Handle campaign with short name
@pytest.mark.order(1)
def test_gti_campaign_short_name(
    campaign_with_short_name: GTICampaignData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test handling GTI campaign with name too short."""
    # Given a GTI campaign with short name
    mapper = _given_gti_campaign_mapper(
        campaign_with_short_name, mock_organization, mock_tlp_marking
    )
    # When converting to STIX
    # Then should raise ValueError
    _when_convert_to_stix_raises_error(
        mapper, ValueError, "Campaign name must be at least 2 characters long"
    )


# Scenario: Handle campaign with empty name
@pytest.mark.order(1)
def test_gti_campaign_empty_name(
    campaign_with_empty_name: GTICampaignData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test handling GTI campaign with empty name."""
    # Given a GTI campaign with empty name
    mapper = _given_gti_campaign_mapper(
        campaign_with_empty_name, mock_organization, mock_tlp_marking
    )
    # When converting to STIX
    # Then should raise ValueError
    _when_convert_to_stix_raises_error(
        mapper, ValueError, "Campaign name must be at least 2 characters long"
    )


# Scenario: Test extract seen dates method
@pytest.mark.order(1)
def test_extract_seen_dates() -> None:
    """Test extracting seen dates from campaign attributes."""
    # Given campaign attributes with seen dates
    attributes = CampaignModelFactory.build(
        first_seen_details=[ActivityDetailFactory.build(value="2023-01-01T00:00:00Z")],
        last_seen_details=[ActivityDetailFactory.build(value="2023-12-31T23:59:59Z")],
    )
    # When extracting seen dates
    first_seen, last_seen = _when_extract_seen_dates(attributes)
    # Then seen dates should be extracted correctly
    _then_seen_dates_extracted_correctly(first_seen, last_seen)


# Scenario: Test extract labels method
@pytest.mark.order(1)
def test_extract_labels() -> None:
    """Test extracting labels from campaign attributes."""
    # Given campaign attributes with tags
    attributes = CampaignModelFactory.build(
        tags_details=[
            TagDetailFactory.build(value="Campaign"),
            TagDetailFactory.build(value="Advanced Persistent Threat"),
        ]
    )
    # When extracting labels
    labels = _when_extract_labels(attributes)
    # Then labels should be extracted correctly
    _then_labels_extracted_correctly(labels, ["Campaign", "Advanced Persistent Threat"])


# =====================
# Additional Edge Cases
# =====================


# Scenario: Test campaign with missing hasattr conditions
@pytest.mark.order(1)
def test_campaign_missing_hasattr() -> None:
    """Test campaign without hasattr conditions."""
    # Given a campaign object without attributes property
    campaign = GTICampaignDataFactory.build()
    delattr(campaign, "attributes")

    mock_org = Identity(
        id=f"identity--{uuid4()}", name="Test", identity_class="organization"
    )
    mock_tlp = MarkingDefinition(
        id=f"marking-definition--{uuid4()}",
        definition_type="statement",
        definition={"statement": "test"},
    )
    mapper = GTICampaignToSTIXCampaign(campaign, mock_org, mock_tlp)

    # When converting to STIX
    # Then should raise ValueError
    _when_convert_to_stix_raises_error(mapper, ValueError, "Invalid GTI campaign data")


# Scenario: Test edge case with empty string values
@pytest.mark.order(1)
def test_campaign_empty_string_values(
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test handling campaign with empty string values."""
    # Given a campaign with empty string values
    campaign = GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            tags_details=[TagDetailFactory.build(value="")],
        )
    )

    # When converting to STIX
    mapper = _given_gti_campaign_mapper(campaign, mock_organization, mock_tlp_marking)
    stix_campaign = _when_convert_to_stix(mapper)

    # Then should handle empty strings gracefully
    assert stix_campaign is not None  # noqa: S101
    assert stix_campaign.labels == []  # noqa: S101


# Scenario: Test unicode characters in campaign data
@pytest.mark.order(1)
def test_campaign_unicode_characters(
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test handling campaign with unicode characters."""
    # Given a campaign with unicode characters
    campaign = GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            name="🔥 Unicode Campaign 测试",
            description="Campaign with émojis and spécial charactérs: αβγδε",
        )
    )

    # When converting to STIX
    mapper = _given_gti_campaign_mapper(campaign, mock_organization, mock_tlp_marking)
    stix_campaign = _when_convert_to_stix(mapper)

    # Then should preserve unicode characters
    assert stix_campaign.name == "🔥 Unicode Campaign 测试"  # noqa: S101
    assert (  # noqa: S101
        stix_campaign.description
        == "Campaign with émojis and spécial charactérs: αβγδε"
    )


# Scenario: Test very long strings
@pytest.mark.order(1)
def test_campaign_long_strings(
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test handling campaign with very long strings."""
    # Given a campaign with very long strings
    long_string = "A" * 10000  # 10K characters
    campaign = GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            name=long_string,
            description=long_string,
        )
    )

    # When converting to STIX
    mapper = _given_gti_campaign_mapper(campaign, mock_organization, mock_tlp_marking)
    stix_campaign = _when_convert_to_stix(mapper)

    # Then should handle long strings without truncation
    assert len(stix_campaign.name) == 10000  # noqa: S101
    assert len(stix_campaign.description) == 10000  # noqa: S101


# Scenario: Test boundary timestamp values
@pytest.mark.parametrize(
    "creation_date,modification_date",
    [
        (0, 1),  # Epoch start
        (1672531200, 1672617600),  # Normal dates
        (2147483647, 2147483647),  # 32-bit max timestamp
    ],
)
@pytest.mark.order(1)
def test_campaign_boundary_timestamps(
    creation_date: int,
    modification_date: int,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test handling campaign with boundary timestamp values."""
    # Given a campaign with boundary timestamps
    campaign = GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            creation_date=creation_date,
            last_modification_date=modification_date,
        )
    )

    # When converting to STIX
    mapper = _given_gti_campaign_mapper(campaign, mock_organization, mock_tlp_marking)
    stix_campaign = _when_convert_to_stix(mapper)

    # Then should handle boundary timestamps
    expected_created = datetime.fromtimestamp(creation_date, tz=timezone.utc)
    expected_modified = datetime.fromtimestamp(modification_date, tz=timezone.utc)
    assert stix_campaign.created == expected_created  # noqa: S101
    assert stix_campaign.modified == expected_modified  # noqa: S101


# =====================
# GWT Gherkin-style functions
# =====================


# Given setup GTI campaign mapper
def _given_gti_campaign_mapper(
    campaign: GTICampaignData,
    organization: Identity,
    tlp_marking: MarkingDefinition,
) -> GTICampaignToSTIXCampaign:
    """Set up the GTI campaign mapper."""
    return GTICampaignToSTIXCampaign(campaign, organization, tlp_marking)


# When convert to STIX
def _when_convert_to_stix(mapper: GTICampaignToSTIXCampaign) -> Any:
    """Convert GTI campaign to STIX."""
    return mapper.to_stix()


# When convert to STIX raises error
def _when_convert_to_stix_raises_error(
    mapper: GTICampaignToSTIXCampaign,
    expected_exception: type,
    expected_message: str,
) -> None:
    """Test that conversion raises expected error."""
    with pytest.raises(expected_exception, match=expected_message):
        mapper.to_stix()


# When extract seen dates
def _when_extract_seen_dates(
    attributes: CampaignModel,
) -> tuple[datetime | None, datetime | None]:
    """Extract seen dates from campaign attributes."""
    return GTICampaignToSTIXCampaign._get_activity_timestamps(attributes)


# When extract labels
def _when_extract_labels(attributes: CampaignModel) -> list[str]:
    """Extract labels from campaign attributes."""
    return GTICampaignToSTIXCampaign._extract_labels(attributes)


# Then STIX campaign created successfully
def _then_stix_campaign_created_successfully(
    stix_campaign: Any,
    gti_campaign: GTICampaignData,
    organization: Identity,
    tlp_marking: MarkingDefinition,
) -> None:
    """Check if STIX campaign was created successfully."""
    assert stix_campaign is not None  # noqa: S101
    assert stix_campaign.type == "campaign"  # noqa: S101
    assert stix_campaign.name == gti_campaign.attributes.name  # noqa: S101
    assert (  # noqa: S101
        stix_campaign.description == gti_campaign.attributes.description
    )
    assert stix_campaign.created_by_ref == organization.id  # noqa: S101
    assert tlp_marking.id in stix_campaign.object_marking_refs  # noqa: S101

    expected_created = datetime.fromtimestamp(
        gti_campaign.attributes.creation_date, tz=timezone.utc
    )
    expected_modified = datetime.fromtimestamp(
        gti_campaign.attributes.last_modification_date, tz=timezone.utc
    )
    assert stix_campaign.created == expected_created  # noqa: S101
    assert stix_campaign.modified == expected_modified  # noqa: S101


# Then STIX campaign has seen dates
def _then_stix_campaign_has_seen_dates(
    stix_campaign: Any, gti_campaign: GTICampaignData
) -> None:
    """Check if STIX campaign has seen dates."""
    if (
        gti_campaign.attributes.first_seen_details
        and len(gti_campaign.attributes.first_seen_details) > 0
    ):
        assert stix_campaign.first_seen is not None  # noqa: S101
        assert isinstance(stix_campaign.first_seen, datetime)  # noqa: S101

    if (
        gti_campaign.attributes.last_seen_details
        and len(gti_campaign.attributes.last_seen_details) > 0
    ):
        assert stix_campaign.last_seen is not None  # noqa: S101
        assert isinstance(stix_campaign.last_seen, datetime)  # noqa: S101


# Then STIX campaign has labels
def _then_stix_campaign_has_labels(
    stix_campaign: Any, gti_campaign: GTICampaignData
) -> None:
    """Check if STIX campaign has labels."""
    if gti_campaign.attributes.tags_details:
        assert stix_campaign.labels is not None  # noqa: S101
        assert len(stix_campaign.labels) > 0  # noqa: S101


# Then STIX campaign handles invalid dates
def _then_stix_campaign_handles_invalid_dates(stix_campaign: Any) -> None:
    """Check if STIX campaign handles invalid dates gracefully."""
    assert stix_campaign is not None  # noqa: S101


# Then STIX campaign handles empty collections
def _then_stix_campaign_handles_empty_collections(stix_campaign: Any) -> None:
    """Check if STIX campaign handles empty collections gracefully."""
    assert stix_campaign is not None  # noqa: S101


# Then seen dates extracted correctly
def _then_seen_dates_extracted_correctly(
    first_seen: datetime | None, last_seen: datetime | None
) -> None:
    """Check if seen dates were extracted correctly."""
    assert first_seen is not None  # noqa: S101
    assert last_seen is not None  # noqa: S101
    assert isinstance(first_seen, datetime)  # noqa: S101
    assert isinstance(last_seen, datetime)  # noqa: S101
    assert first_seen.year == 2023  # noqa: S101
    assert last_seen.year == 2023  # noqa: S101


# Then labels extracted correctly
def _then_labels_extracted_correctly(labels: list[str], expected: list[str]) -> None:
    """Check if labels were extracted correctly."""
    assert labels is not None  # noqa: S101
    assert len(labels) == len(expected)  # noqa: S101
    for expected_label in expected:
        assert expected_label in labels  # noqa: S101


# Scenario: Test GTI campaign mapper initialization
@pytest.mark.order(1)
def test_gti_campaign_mapper_initialization(
    minimal_campaign_data: GTICampaignData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTICampaignToSTIXCampaign mapper initialization."""
    # Given valid GTI campaign data, organization, and TLP marking objects
    # When creating a new GTICampaignToSTIXCampaign mapper instance
    mapper = GTICampaignToSTIXCampaign(
        campaign=minimal_campaign_data,
        organization=mock_organization,
        tlp_marking=mock_tlp_marking,
    )

    # Then the mapper should be initialized correctly
    assert mapper.campaign == minimal_campaign_data  # noqa: S101
    assert mapper.organization == mock_organization  # noqa: S101
    assert mapper.tlp_marking == mock_tlp_marking  # noqa: S101
