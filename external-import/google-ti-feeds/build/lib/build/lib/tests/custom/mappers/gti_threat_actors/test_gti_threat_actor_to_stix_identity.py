"""Tests for the GTIThreatActorToSTIXIdentity mapper."""

from uuid import uuid4

import pytest
from connector.src.custom.mappers.gti_threat_actors.gti_threat_actor_to_stix_identity import (
    GTIThreatActorToSTIXIdentity,
)
from connector.src.custom.models.gti.gti_threat_actor_model import (
    GTIThreatActorData,
    TargetedIndustry,
    ThreatActorModel,
)
from polyfactory.factories.pydantic_factory import ModelFactory
from polyfactory.fields import Use
from stix2.v21 import Identity, MarkingDefinition  # type: ignore


class TargetedIndustryFactory(ModelFactory[TargetedIndustry]):
    """Factory for TargetedIndustry model."""

    __model__ = TargetedIndustry


class ThreatActorModelFactory(ModelFactory[ThreatActorModel]):
    """Factory for ThreatActorModel."""

    __model__ = ThreatActorModel


class GTIThreatActorDataFactory(ModelFactory[GTIThreatActorData]):
    """Factory for GTIThreatActorData."""

    __model__ = GTIThreatActorData

    type = "threat_actor"
    attributes = Use(ThreatActorModelFactory.build)


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
def threat_actor_with_industries() -> GTIThreatActorData:
    """Fixture for GTI threat actor with targeted industries."""
    return GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(
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
def threat_actor_with_multiple_industries() -> GTIThreatActorData:
    """Fixture for GTI threat actor with multiple targeted industries."""
    return GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(
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
def threat_actor_without_industries() -> GTIThreatActorData:
    """Fixture for GTI threat actor without targeted industries."""
    return GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(targeted_industries_tree=None)
    )


@pytest.fixture
def threat_actor_with_empty_industries() -> GTIThreatActorData:
    """Fixture for GTI threat actor with empty industries list."""
    return GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(targeted_industries_tree=[])
    )


@pytest.fixture
def threat_actor_without_attributes() -> GTIThreatActorData:
    """Fixture for GTI threat actor without attributes."""
    return GTIThreatActorDataFactory.build(attributes=None)


@pytest.fixture
def threat_actor_with_industry_without_group() -> GTIThreatActorData:
    """Fixture for GTI threat actor with empty industry group."""
    return GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(
            targeted_industries_tree=[
                TargetedIndustryFactory.build(
                    industry_group="",
                    industry="Banking",
                    description="Industry with empty group",
                    confidence="high",
                )
            ]
        )
    )


@pytest.fixture
def threat_actor_with_empty_industry_group() -> GTIThreatActorData:
    """Fixture for GTI threat actor with empty industry group."""
    return GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(
            targeted_industries_tree=[
                TargetedIndustryFactory.build(
                    industry_group="",
                    industry="Banking",
                    description="Empty industry group",
                    confidence="high",
                )
            ]
        )
    )


@pytest.fixture
def threat_actor_with_long_industry_name() -> GTIThreatActorData:
    """Fixture for GTI threat actor with very long industry name."""
    return GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(
            targeted_industries_tree=[
                TargetedIndustryFactory.build(
                    industry_group="A" * 500,
                    industry="Banking",
                    description="Very long industry group name",
                    confidence="high",
                )
            ]
        )
    )


@pytest.fixture
def threat_actor_with_special_characters_in_industry() -> GTIThreatActorData:
    """Fixture for GTI threat actor with special characters in industry name."""
    return GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(
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
def threat_actor_with_mixed_valid_invalid_industries() -> GTIThreatActorData:
    """Fixture for GTI threat actor with mixed valid and invalid industries."""
    return GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(
            targeted_industries_tree=[
                TargetedIndustryFactory.build(
                    industry_group="Financial Services",
                    industry="Banking",
                    description="Valid industry",
                    confidence="high",
                ),
                TargetedIndustryFactory.build(
                    industry_group="",
                    industry="Software",
                    description="Invalid industry with empty group",
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
                    industry="Government",
                    description="Invalid industry with whitespace-only group",
                    confidence="low",
                ),
            ]
        )
    )


@pytest.mark.order(1)
def test_gti_threat_actor_to_stix_identity_with_industries(
    threat_actor_with_industries, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI threat actor with industries to STIX identity sectors."""
    # GIVEN: A GTI threat actor containing targeted industries information
    # with valid industry groups for sector identity creation
    mapper = _given_gti_threat_actor_identity_mapper(
        threat_actor_with_industries, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI threat actor data to STIX identity objects
    identities = _when_convert_to_stix(mapper)

    # THEN: STIX Identity objects should be created successfully
    # with one identity per industry group
    _then_stix_identities_created_successfully(identities)
    assert len(identities) == 2  # noqa: S101
    _then_stix_identity_has_correct_properties(identities[0], mock_organization)
    _then_stix_identity_has_correct_sector_properties(
        identities[0], "Financial Services"
    )
    _then_stix_identity_has_correct_sector_properties(identities[1], "Technology")


@pytest.mark.order(1)
def test_gti_threat_actor_to_stix_identity_with_multiple_industries(
    threat_actor_with_multiple_industries, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI threat actor with multiple industries."""
    # GIVEN: A GTI threat actor containing multiple targeted industries
    # with different industry groups and confidence levels
    mapper = _given_gti_threat_actor_identity_mapper(
        threat_actor_with_multiple_industries, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI threat actor data to STIX identity objects
    identities = _when_convert_to_stix(mapper)

    # THEN: STIX Identity objects should be created for all industry groups
    # with proper sector classification for each industry
    _then_stix_identities_created_successfully(identities)
    assert len(identities) == 4  # noqa: S101
    _then_stix_identity_has_correct_properties(identities[0], mock_organization)

    # Verify all expected industry groups are present
    industry_names = [identity.name for identity in identities]
    assert "Financial Services" in industry_names  # noqa: S101
    assert "Healthcare" in industry_names  # noqa: S101
    assert "Government" in industry_names  # noqa: S101
    assert "Technology" in industry_names  # noqa: S101


@pytest.mark.order(1)
def test_gti_threat_actor_to_stix_identity_without_industries(
    threat_actor_without_industries, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI threat actor without industries."""
    # GIVEN: A GTI threat actor with no targeted industries defined
    # indicating no specific industry targeting information is available
    mapper = _given_gti_threat_actor_identity_mapper(
        threat_actor_without_industries, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI threat actor data to STIX identity objects
    identities = _when_convert_to_stix(mapper)

    # THEN: An empty list should be returned
    # since no industry information is available to convert
    assert isinstance(identities, list)  # noqa: S101
    assert len(identities) == 0  # noqa: S101


@pytest.mark.order(1)
def test_gti_threat_actor_to_stix_identity_with_empty_industries(
    threat_actor_with_empty_industries, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI threat actor with empty industries list."""
    # GIVEN: A GTI threat actor with empty list for targeted industries
    # representing a case where industry fields exist but contain no data
    mapper = _given_gti_threat_actor_identity_mapper(
        threat_actor_with_empty_industries, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI threat actor data to STIX identity objects
    identities = _when_convert_to_stix(mapper)

    # THEN: An empty list should be returned
    # since empty industry lists provide no sector information
    assert isinstance(identities, list)  # noqa: S101
    assert len(identities) == 0  # noqa: S101


@pytest.mark.order(1)
def test_gti_threat_actor_to_stix_identity_without_attributes(
    threat_actor_without_attributes, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI threat actor without attributes raises ValueError."""
    # GIVEN: A GTI threat actor with attributes field set to None
    # making it impossible to access any threat actor data including industries
    mapper = _given_gti_threat_actor_identity_mapper(
        threat_actor_without_attributes, mock_organization, mock_tlp_marking
    )

    # WHEN: Attempting to convert the GTI threat actor data to STIX identity objects
    # THEN: A ValueError should be raised with message about invalid attributes
    _when_convert_to_stix_raises_error(
        mapper, ValueError, "Invalid threat actor attributes"
    )


@pytest.mark.order(1)
def test_gti_threat_actor_to_stix_identity_with_industry_without_group(
    threat_actor_with_industry_without_group, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI threat actor with empty industry group."""
    # GIVEN: A GTI threat actor containing industry data with empty industry group
    # which is invalid for creating meaningful sector identities
    mapper = _given_gti_threat_actor_identity_mapper(
        threat_actor_with_industry_without_group, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI threat actor data to STIX identity objects
    identities = _when_convert_to_stix(mapper)

    # THEN: No identities should be created since industry group is empty
    # as the group field is required for sector identity creation
    assert isinstance(identities, list)  # noqa: S101
    assert len(identities) == 0  # noqa: S101


@pytest.mark.order(1)
def test_gti_threat_actor_to_stix_identity_with_empty_industry_group(
    threat_actor_with_empty_industry_group, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI threat actor with empty industry group."""
    # GIVEN: A GTI threat actor containing industry data with empty industry group
    # representing malformed industry data with missing group classification
    mapper = _given_gti_threat_actor_identity_mapper(
        threat_actor_with_empty_industry_group, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI threat actor data to STIX identity objects
    identities = _when_convert_to_stix(mapper)

    # THEN: No identities should be created since industry group is empty
    # as empty strings are treated as invalid for sector classification
    assert isinstance(identities, list)  # noqa: S101
    assert len(identities) == 0  # noqa: S101


@pytest.mark.order(1)
def test_gti_threat_actor_to_stix_identity_with_long_industry_name(
    threat_actor_with_long_industry_name, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI threat actor with very long industry name."""
    # GIVEN: A GTI threat actor containing extremely long industry group name
    # to test boundary conditions and ensure long names are handled properly
    mapper = _given_gti_threat_actor_identity_mapper(
        threat_actor_with_long_industry_name, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI threat actor data to STIX identity objects
    identities = _when_convert_to_stix(mapper)

    # THEN: STIX Identity object should be created successfully
    # preserving the full length of the industry name without truncation
    _then_stix_identities_created_successfully(identities)
    assert len(identities) == 1  # noqa: S101
    _then_stix_identity_preserves_long_industry_name(identities[0])


@pytest.mark.order(1)
def test_gti_threat_actor_to_stix_identity_with_special_characters(
    threat_actor_with_special_characters_in_industry,
    mock_organization,
    mock_tlp_marking,
):
    """Test conversion of GTI threat actor with special characters in industry name."""
    # GIVEN: A GTI threat actor containing industry names with special characters
    # (ampersands, spaces) to test character encoding and preservation
    mapper = _given_gti_threat_actor_identity_mapper(
        threat_actor_with_special_characters_in_industry,
        mock_organization,
        mock_tlp_marking,
    )

    # WHEN: Converting the GTI threat actor data to STIX identity objects
    identities = _when_convert_to_stix(mapper)

    # THEN: STIX Identity object should be created successfully
    # preserving all special characters in the industry name without modification
    _then_stix_identities_created_successfully(identities)
    assert len(identities) == 1  # noqa: S101
    _then_stix_identity_preserves_special_characters(identities[0])


@pytest.mark.order(1)
def test_gti_threat_actor_to_stix_identity_with_mixed_valid_invalid_industries(
    threat_actor_with_mixed_valid_invalid_industries,
    mock_organization,
    mock_tlp_marking,
):
    """Test conversion of GTI threat actor with mixed valid and invalid industries."""
    # GIVEN: A GTI threat actor containing both valid and invalid industry data
    # to test selective processing of only valid industry information
    mapper = _given_gti_threat_actor_identity_mapper(
        threat_actor_with_mixed_valid_invalid_industries,
        mock_organization,
        mock_tlp_marking,
    )

    # WHEN: Converting the GTI threat actor data to STIX identity objects
    identities = _when_convert_to_stix(mapper)

    # THEN: Only valid industries should be processed into STIX Identity objects
    # while invalid industries are skipped without affecting valid ones
    _then_stix_identities_created_successfully(identities)
    assert len(identities) == 2  # noqa: S101  # Only valid industries

    # Verify only valid industry groups are present
    industry_names = [identity.name for identity in identities]
    assert "Financial Services" in industry_names  # noqa: S101
    assert "Healthcare" in industry_names  # noqa: S101


@pytest.mark.order(1)
def test_process_industry_with_valid_data(
    threat_actor_with_industries, mock_organization, mock_tlp_marking
):
    """Test processing of industry with valid data."""
    # GIVEN: A GTI threat actor identity mapper with valid industry data
    mapper = _given_gti_threat_actor_identity_mapper(
        threat_actor_with_industries, mock_organization, mock_tlp_marking
    )
    industry_data = threat_actor_with_industries.attributes.targeted_industries_tree[0]

    # WHEN: Processing the industry data
    identity = mapper._process_industry(industry_data)

    # THEN: A valid STIX Identity object should be created
    # with proper sector properties mapped from industry data
    assert identity is not None  # noqa: S101
    _then_stix_identity_has_correct_sector_properties(identity, "Financial Services")


@pytest.mark.order(1)
def test_process_industry_without_industry_group(mock_organization, mock_tlp_marking):
    """Test processing of industry with empty industry group."""
    # GIVEN: A GTI threat actor identity mapper and industry data with empty group
    threat_actor = GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(
            targeted_industries_tree=[
                TargetedIndustryFactory.build(
                    industry_group="",
                    industry="Banking",
                    description="Industry with empty group",
                )
            ]
        )
    )
    mapper = _given_gti_threat_actor_identity_mapper(
        threat_actor, mock_organization, mock_tlp_marking
    )
    industry_data = threat_actor.attributes.targeted_industries_tree[0]

    # WHEN: Processing the industry data with empty group
    identity = mapper._process_industry(industry_data)

    # THEN: No identity should be created
    assert identity is None  # noqa: S101


@pytest.mark.order(1)
def test_create_sector_with_valid_data(
    threat_actor_with_industries, mock_organization, mock_tlp_marking
):
    """Test creating sector with valid industry data."""
    # GIVEN: A GTI threat actor identity mapper with valid industry data
    mapper = _given_gti_threat_actor_identity_mapper(
        threat_actor_with_industries, mock_organization, mock_tlp_marking
    )
    industry_data = threat_actor_with_industries.attributes.targeted_industries_tree[0]

    # WHEN: Creating a sector identity from the industry data
    identity = mapper._create_sector(industry_data)

    # THEN: A valid STIX Identity object should be created
    # with proper sector classification and properties
    assert identity is not None  # noqa: S101
    _then_stix_identity_has_correct_sector_properties(identity, "Financial Services")
    _then_stix_identity_has_correct_properties(identity, mock_organization)


@pytest.mark.order(1)
def test_gti_threat_actor_identity_mapper_initialization(
    threat_actor_with_industries, mock_organization, mock_tlp_marking
):
    """Test GTIThreatActorToSTIXIdentity mapper initialization."""
    # GIVEN: Valid GTI threat actor data, organization, and TLP marking objects
    # for initializing the mapper with all required dependencies
    # WHEN: Creating a new GTIThreatActorToSTIXIdentity mapper instance
    mapper = GTIThreatActorToSTIXIdentity(
        threat_actor=threat_actor_with_industries,
        organization=mock_organization,
        tlp_marking=mock_tlp_marking,
    )

    # THEN: The mapper should be initialized correctly
    # with all provided objects properly assigned to instance attributes
    assert mapper.threat_actor == threat_actor_with_industries  # noqa: S101
    assert mapper.organization == mock_organization  # noqa: S101
    assert mapper.tlp_marking == mock_tlp_marking  # noqa: S101


def _given_gti_threat_actor_identity_mapper(
    threat_actor: GTIThreatActorData,
    organization: Identity,
    tlp_marking: MarkingDefinition,
) -> GTIThreatActorToSTIXIdentity:
    """Create a GTIThreatActorToSTIXIdentity mapper instance."""
    return GTIThreatActorToSTIXIdentity(
        threat_actor=threat_actor,
        organization=organization,
        tlp_marking=tlp_marking,
    )


def _when_convert_to_stix(mapper: GTIThreatActorToSTIXIdentity) -> list:
    """Convert GTI threat actor to STIX identities."""
    return mapper.to_stix()


def _when_convert_to_stix_raises_error(
    mapper: GTIThreatActorToSTIXIdentity, error_type: type, error_message: str
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
