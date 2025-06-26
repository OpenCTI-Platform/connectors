"""Module to test the GTI threat actor to STIX intrusion set mapper."""

from datetime import datetime
from typing import Any, List, Optional
from uuid import uuid4

import pytest
from connector.src.custom.mappers.gti_reports.gti_threat_actor_to_stix_intrusion_set import (
    GTIThreatActorToSTIXIntrusionSet,
)
from connector.src.custom.models.gti_reports.gti_threat_actor_model import (
    AltNameDetail,
    GTIThreatActorData,
    Motivation,
    SeenDetail,
    TagDetail,
    TargetedIndustry,
    ThreatActorModel,
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
    value = "APT Example"


class SeenDetailFactory(ModelFactory[SeenDetail]):
    """Factory for SeenDetail model."""

    __model__ = SeenDetail

    confidence = "high"
    value = "2023-01-01T00:00:00Z"


class MotivationFactory(ModelFactory[Motivation]):
    """Factory for Motivation model."""

    __model__ = Motivation

    confidence = "high"
    value = "Financial"


class TagDetailFactory(ModelFactory[TagDetail]):
    """Factory for TagDetail model."""

    __model__ = TagDetail

    confidence = "high"
    value = "APT"


class TargetedIndustryFactory(ModelFactory[TargetedIndustry]):
    """Factory for TargetedIndustry model."""

    __model__ = TargetedIndustry

    confidence = "high"
    industry_group = "Financial Services"


class ThreatActorModelFactory(ModelFactory[ThreatActorModel]):
    """Factory for ThreatActorModel."""

    __model__ = ThreatActorModel

    name = "Test Threat Actor"
    creation_date = 1672531200
    last_modification_date = 1672617600
    description = "A test threat actor"
    private = False


class GTIThreatActorDataFactory(ModelFactory[GTIThreatActorData]):
    """Factory for GTIThreatActorData."""

    __model__ = GTIThreatActorData

    type = "threat_actor"
    attributes = Use(ThreatActorModelFactory.build)


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
def minimal_threat_actor_data() -> GTIThreatActorData:
    """Fixture for minimal threat actor data."""
    return GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(
            alt_names_details=None,
            first_seen_details=None,
            last_seen_details=None,
            motivations=None,
            tags_details=None,
            targeted_industries_tree=None,
        )
    )


@pytest.fixture
def threat_actor_with_aliases() -> GTIThreatActorData:
    """Fixture for threat actor data with aliases."""
    return GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(
            alt_names_details=[
                AltNameDetailFactory.build(value="APT Example"),
                AltNameDetailFactory.build(value="Example Group"),
            ]
        )
    )


@pytest.fixture
def threat_actor_with_seen_dates() -> GTIThreatActorData:
    """Fixture for threat actor data with seen dates."""
    return GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(
            first_seen_details=[SeenDetailFactory.build(value="2023-01-01T00:00:00Z")],
            last_seen_details=[SeenDetailFactory.build(value="2023-12-31T23:59:59Z")],
        )
    )


@pytest.fixture
def threat_actor_with_motivations() -> GTIThreatActorData:
    """Fixture for threat actor data with motivations."""
    return GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(
            motivations=[
                MotivationFactory.build(value="Financial"),
                MotivationFactory.build(value="Corporate Espionage"),
            ]
        )
    )


@pytest.fixture
def threat_actor_with_tags() -> GTIThreatActorData:
    """Fixture for threat actor data with tags."""
    return GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(
            tags_details=[
                TagDetailFactory.build(value="APT"),
                TagDetailFactory.build(value="Advanced Persistent Threat"),
            ]
        )
    )


@pytest.fixture
def threat_actor_with_goals() -> GTIThreatActorData:
    """Fixture for threat actor data with goals."""
    return GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(
            targeted_industries_tree=[
                TargetedIndustryFactory.build(industry_group="Financial Services"),
                TargetedIndustryFactory.build(industry_group="Healthcare"),
            ]
        )
    )


@pytest.fixture
def threat_actor_with_all_data() -> GTIThreatActorData:
    """Fixture for threat actor data with all optional fields."""
    return GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(
            alt_names_details=[AltNameDetailFactory.build(value="APT Example")],
            first_seen_details=[SeenDetailFactory.build(value="2023-01-01T00:00:00Z")],
            last_seen_details=[SeenDetailFactory.build(value="2023-12-31T23:59:59Z")],
            motivations=[MotivationFactory.build(value="Financial")],
            tags_details=[TagDetailFactory.build(value="APT")],
            targeted_industries_tree=[
                TargetedIndustryFactory.build(industry_group="Financial Services")
            ],
        )
    )


@pytest.fixture
def threat_actor_without_attributes() -> GTIThreatActorData:
    """Fixture for threat actor data without attributes."""
    return GTIThreatActorDataFactory.build(attributes=None)


@pytest.fixture
def threat_actor_with_invalid_dates() -> GTIThreatActorData:
    """Fixture for threat actor data with invalid date formats."""
    return GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(
            first_seen_details=[SeenDetailFactory.build(value="invalid-date-format")],
            last_seen_details=[SeenDetailFactory.build(value="2023-13-32T25:61:61Z")],
        )
    )


@pytest.fixture
def threat_actor_with_unmapped_motivations() -> GTIThreatActorData:
    """Fixture for threat actor data with unmapped motivations."""
    return GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(
            motivations=[
                MotivationFactory.build(value="Unknown Motivation"),
                MotivationFactory.build(value="Custom Motivation"),
            ]
        )
    )


@pytest.fixture
def threat_actor_with_empty_collections() -> GTIThreatActorData:
    """Fixture for threat actor data with empty collections."""
    return GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(
            alt_names_details=[],
            first_seen_details=[],
            last_seen_details=[],
            motivations=[],
            tags_details=[],
            targeted_industries_tree=[],
        )
    )


# =====================
# Test Cases
# =====================


# Scenario: Create STIX intrusion set with minimal required data
def test_gti_threat_actor_to_stix_minimal_data(
    minimal_threat_actor_data: GTIThreatActorData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test converting GTI threat actor with minimal data to STIX."""
    # Given a GTI threat actor with minimal data
    mapper = _given_gti_threat_actor_mapper(
        minimal_threat_actor_data, mock_organization, mock_tlp_marking
    )
    # When converting to STIX
    stix_intrusion_set = _when_convert_to_stix(mapper)
    # Then STIX intrusion set should be created with basic fields
    _then_stix_intrusion_set_created_successfully(
        stix_intrusion_set,
        minimal_threat_actor_data,
        mock_organization,
        mock_tlp_marking,
    )


# Scenario: Create STIX intrusion set with aliases
def test_gti_threat_actor_to_stix_with_aliases(
    threat_actor_with_aliases: GTIThreatActorData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test converting GTI threat actor with aliases to STIX."""
    # Given a GTI threat actor with aliases
    mapper = _given_gti_threat_actor_mapper(
        threat_actor_with_aliases, mock_organization, mock_tlp_marking
    )
    # When converting to STIX
    stix_intrusion_set = _when_convert_to_stix(mapper)
    # Then STIX intrusion set should include aliases
    _then_stix_intrusion_set_created_successfully(
        stix_intrusion_set,
        threat_actor_with_aliases,
        mock_organization,
        mock_tlp_marking,
    )
    _then_stix_intrusion_set_has_aliases(stix_intrusion_set, threat_actor_with_aliases)


# Scenario: Create STIX intrusion set with seen dates
def test_gti_threat_actor_to_stix_with_seen_dates(
    threat_actor_with_seen_dates: GTIThreatActorData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test converting GTI threat actor with seen dates to STIX."""
    # Given a GTI threat actor with seen dates
    mapper = _given_gti_threat_actor_mapper(
        threat_actor_with_seen_dates, mock_organization, mock_tlp_marking
    )
    # When converting to STIX
    stix_intrusion_set = _when_convert_to_stix(mapper)
    # Then STIX intrusion set should include seen dates
    _then_stix_intrusion_set_created_successfully(
        stix_intrusion_set,
        threat_actor_with_seen_dates,
        mock_organization,
        mock_tlp_marking,
    )
    _then_stix_intrusion_set_has_seen_dates(
        stix_intrusion_set, threat_actor_with_seen_dates
    )


# Scenario: Create STIX intrusion set with motivations
def test_gti_threat_actor_to_stix_with_motivations(
    threat_actor_with_motivations: GTIThreatActorData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test converting GTI threat actor with motivations to STIX."""
    # Given a GTI threat actor with motivations
    mapper = _given_gti_threat_actor_mapper(
        threat_actor_with_motivations, mock_organization, mock_tlp_marking
    )
    # When converting to STIX
    stix_intrusion_set = _when_convert_to_stix(mapper)
    # Then STIX intrusion set should include motivations
    _then_stix_intrusion_set_created_successfully(
        stix_intrusion_set,
        threat_actor_with_motivations,
        mock_organization,
        mock_tlp_marking,
    )
    _then_stix_intrusion_set_has_motivations(
        stix_intrusion_set, threat_actor_with_motivations
    )


# Scenario: Create STIX intrusion set with tags/labels
def test_gti_threat_actor_to_stix_with_tags(
    threat_actor_with_tags: GTIThreatActorData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test converting GTI threat actor with tags to STIX."""
    # Given a GTI threat actor with tags
    mapper = _given_gti_threat_actor_mapper(
        threat_actor_with_tags, mock_organization, mock_tlp_marking
    )
    # When converting to STIX
    stix_intrusion_set = _when_convert_to_stix(mapper)
    # Then STIX intrusion set should include labels
    _then_stix_intrusion_set_created_successfully(
        stix_intrusion_set,
        threat_actor_with_tags,
        mock_organization,
        mock_tlp_marking,
    )


# Scenario: Create STIX intrusion set with goals
def test_gti_threat_actor_to_stix_with_goals(
    threat_actor_with_goals: GTIThreatActorData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test converting GTI threat actor with goals to STIX."""
    # Given a GTI threat actor with goals
    mapper = _given_gti_threat_actor_mapper(
        threat_actor_with_goals, mock_organization, mock_tlp_marking
    )
    # When converting to STIX
    stix_intrusion_set = _when_convert_to_stix(mapper)
    # Then STIX intrusion set should include goals
    _then_stix_intrusion_set_created_successfully(
        stix_intrusion_set,
        threat_actor_with_goals,
        mock_organization,
        mock_tlp_marking,
    )


# Scenario: Create STIX intrusion set with all optional data
def test_gti_threat_actor_to_stix_with_all_data(
    threat_actor_with_all_data: GTIThreatActorData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test converting GTI threat actor with all optional data to STIX."""
    # Given a GTI threat actor with all optional data
    mapper = _given_gti_threat_actor_mapper(
        threat_actor_with_all_data, mock_organization, mock_tlp_marking
    )
    # When converting to STIX
    stix_intrusion_set = _when_convert_to_stix(mapper)
    # Then STIX intrusion set should include all data
    _then_stix_intrusion_set_created_successfully(
        stix_intrusion_set,
        threat_actor_with_all_data,
        mock_organization,
        mock_tlp_marking,
    )
    _then_stix_intrusion_set_has_aliases(stix_intrusion_set, threat_actor_with_all_data)
    _then_stix_intrusion_set_has_seen_dates(
        stix_intrusion_set, threat_actor_with_all_data
    )
    _then_stix_intrusion_set_has_motivations(
        stix_intrusion_set, threat_actor_with_all_data
    )


# =====================
# Edge Cases and Error Scenarios
# =====================


# Scenario: Handle threat actor without attributes
def test_gti_threat_actor_to_stix_without_attributes(
    threat_actor_without_attributes: GTIThreatActorData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test handling GTI threat actor without attributes."""
    # Given a GTI threat actor without attributes
    mapper = _given_gti_threat_actor_mapper(
        threat_actor_without_attributes, mock_organization, mock_tlp_marking
    )
    # When converting to STIX
    # Then should raise ValueError
    _when_convert_to_stix_raises_error(
        mapper, ValueError, "Invalid GTI threat actor data"
    )


# Scenario: Handle None threat actor object
def test_gti_threat_actor_none_object(
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test handling None threat actor object."""
    # Given a None threat actor object
    mapper = GTIThreatActorToSTIXIntrusionSet(None, mock_organization, mock_tlp_marking)
    # When converting to STIX
    # Then should raise ValueError
    _when_convert_to_stix_raises_error(
        mapper, ValueError, "Invalid GTI threat actor data"
    )


# Scenario: Handle threat actor with invalid date formats
def test_gti_threat_actor_invalid_dates(
    threat_actor_with_invalid_dates: GTIThreatActorData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test handling GTI threat actor with invalid date formats."""
    # Given a GTI threat actor with invalid dates
    mapper = _given_gti_threat_actor_mapper(
        threat_actor_with_invalid_dates, mock_organization, mock_tlp_marking
    )
    # When converting to STIX
    stix_intrusion_set = _when_convert_to_stix(mapper)
    # Then should handle invalid dates gracefully
    _then_stix_intrusion_set_handles_invalid_dates(stix_intrusion_set)


# Scenario: Handle threat actor with unmapped motivations
def test_gti_threat_actor_unmapped_motivations(
    threat_actor_with_unmapped_motivations: GTIThreatActorData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test handling GTI threat actor with unmapped motivations."""
    # Given a GTI threat actor with unmapped motivations
    mapper = _given_gti_threat_actor_mapper(
        threat_actor_with_unmapped_motivations, mock_organization, mock_tlp_marking
    )
    # When converting to STIX
    stix_intrusion_set = _when_convert_to_stix(mapper)
    # Then should use default motivation for unmapped values
    _then_stix_intrusion_set_handles_unmapped_motivations(stix_intrusion_set)


# Scenario: Handle threat actor with empty collections
def test_gti_threat_actor_empty_collections(
    threat_actor_with_empty_collections: GTIThreatActorData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test handling GTI threat actor with empty collections."""
    # Given a GTI threat actor with empty collections
    mapper = _given_gti_threat_actor_mapper(
        threat_actor_with_empty_collections, mock_organization, mock_tlp_marking
    )
    # When converting to STIX
    stix_intrusion_set = _when_convert_to_stix(mapper)
    # Then should handle empty collections gracefully
    _then_stix_intrusion_set_handles_empty_collections(stix_intrusion_set)


# Scenario: Test motivation mapping variations with open vocabulary
@pytest.mark.parametrize(
    "gti_motivation",
    [
        "Financial",
        "Corporate Espionage",
        "Ideology",
        "Revenge",
        "Notoriety",
        "Accidental",
        "Custom Motivation",
    ],
)
def test_motivation_mapping_variations(
    gti_motivation: str,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test open vocabulary motivation mapping."""
    # Given a threat actor with specific motivation
    threat_actor = GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(
            motivations=[MotivationFactory.build(value=gti_motivation)]
        )
    )

    # When converting to STIX
    mapper = _given_gti_threat_actor_mapper(
        threat_actor, mock_organization, mock_tlp_marking
    )
    stix_intrusion_set = _when_convert_to_stix(mapper)

    # Then motivation should be accepted by open vocabulary
    assert stix_intrusion_set.primary_motivation.value == gti_motivation  # noqa: S101


# Scenario: Test multiple motivations
def test_multiple_motivations(
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test handling multiple motivations."""
    # Given a threat actor with multiple motivations
    threat_actor = GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(
            motivations=[
                MotivationFactory.build(value="Financial"),
                MotivationFactory.build(value="Corporate Espionage"),
                MotivationFactory.build(value="Ideology"),
            ]
        )
    )

    # When converting to STIX
    mapper = _given_gti_threat_actor_mapper(
        threat_actor, mock_organization, mock_tlp_marking
    )
    stix_intrusion_set = _when_convert_to_stix(mapper)

    # Then should have primary and secondary motivations with open vocabulary values
    assert stix_intrusion_set.primary_motivation.value == "Financial"  # noqa: S101
    assert stix_intrusion_set.secondary_motivations is not None  # noqa: S101
    assert len(stix_intrusion_set.secondary_motivations) == 2  # noqa: S101
    secondary_values = [m.value for m in stix_intrusion_set.secondary_motivations]
    assert "Corporate Espionage" in secondary_values  # noqa: S101
    assert "Ideology" in secondary_values  # noqa: S101


# =====================
# GWT Gherkin-style functions
# =====================


# Given setup GTI threat actor mapper
def _given_gti_threat_actor_mapper(
    threat_actor: GTIThreatActorData,
    organization: Identity,
    tlp_marking: MarkingDefinition,
) -> GTIThreatActorToSTIXIntrusionSet:
    """Set up the GTI threat actor mapper."""
    return GTIThreatActorToSTIXIntrusionSet(threat_actor, organization, tlp_marking)


# When convert to STIX
def _when_convert_to_stix(mapper: GTIThreatActorToSTIXIntrusionSet) -> Any:
    """Convert GTI threat actor to STIX."""
    return mapper.to_stix()


# When convert to STIX raises error
def _when_convert_to_stix_raises_error(
    mapper: GTIThreatActorToSTIXIntrusionSet,
    expected_exception: type,
    expected_message: str,
) -> None:
    """Test that conversion raises expected error."""
    with pytest.raises(expected_exception, match=expected_message):
        mapper.to_stix()


# Then STIX intrusion set created successfully
def _then_stix_intrusion_set_created_successfully(
    stix_intrusion_set: Any,
    gti_threat_actor: GTIThreatActorData,
    organization: Identity,
    tlp_marking: MarkingDefinition,
) -> None:
    """Check if STIX intrusion set was created successfully."""
    assert stix_intrusion_set is not None  # noqa: S101
    assert stix_intrusion_set.type == "intrusion-set"  # noqa: S101
    assert stix_intrusion_set.name == gti_threat_actor.attributes.name  # noqa: S101
    assert (  # noqa: S101
        stix_intrusion_set.description == gti_threat_actor.attributes.description
    )
    assert stix_intrusion_set.created_by_ref == organization.id  # noqa: S101
    assert tlp_marking.id in stix_intrusion_set.object_marking_refs  # noqa: S101

    expected_created = datetime.fromtimestamp(gti_threat_actor.attributes.creation_date)
    expected_modified = datetime.fromtimestamp(
        gti_threat_actor.attributes.last_modification_date
    )
    assert stix_intrusion_set.created == expected_created  # noqa: S101
    assert stix_intrusion_set.modified == expected_modified  # noqa: S101


# Then STIX intrusion set has aliases
def _then_stix_intrusion_set_has_aliases(
    stix_intrusion_set: Any, gti_threat_actor: GTIThreatActorData
) -> None:
    """Check if STIX intrusion set has aliases."""
    expected_aliases = [
        alt_name.value
        for alt_name in gti_threat_actor.attributes.alt_names_details
        if alt_name.value
    ]

    if expected_aliases:
        assert stix_intrusion_set.aliases is not None  # noqa: S101
        for expected_alias in expected_aliases:
            assert expected_alias in stix_intrusion_set.aliases  # noqa: S101
    else:
        assert stix_intrusion_set.aliases is None  # noqa: S101


# Then STIX intrusion set has seen dates
def _then_stix_intrusion_set_has_seen_dates(
    stix_intrusion_set: Any, gti_threat_actor: GTIThreatActorData
) -> None:
    """Check if STIX intrusion set has seen dates."""
    if (
        gti_threat_actor.attributes.first_seen_details
        and len(gti_threat_actor.attributes.first_seen_details) > 0
    ):
        assert stix_intrusion_set.first_seen is not None  # noqa: S101
        assert isinstance(stix_intrusion_set.first_seen, datetime)  # noqa: S101

    if (
        gti_threat_actor.attributes.last_seen_details
        and len(gti_threat_actor.attributes.last_seen_details) > 0
    ):
        assert stix_intrusion_set.last_seen is not None  # noqa: S101
        assert isinstance(stix_intrusion_set.last_seen, datetime)  # noqa: S101


# Then STIX intrusion set has motivations
def _then_stix_intrusion_set_has_motivations(
    stix_intrusion_set: Any, gti_threat_actor: GTIThreatActorData
) -> None:
    """Check if STIX intrusion set has motivations."""
    if gti_threat_actor.attributes.motivations:
        assert stix_intrusion_set.primary_motivation is not None  # noqa: S101

        if len(gti_threat_actor.attributes.motivations) > 1:
            assert stix_intrusion_set.secondary_motivations is not None  # noqa: S101
            assert (  # noqa: S101
                len(stix_intrusion_set.secondary_motivations)
                == len(gti_threat_actor.attributes.motivations) - 1
            )


# Then STIX intrusion set handles invalid dates
def _then_stix_intrusion_set_handles_invalid_dates(stix_intrusion_set: Any) -> None:
    """Check if STIX intrusion set handles invalid dates gracefully."""
    assert stix_intrusion_set is not None  # noqa: S101


# Then STIX intrusion set handles unmapped motivations
def _then_stix_intrusion_set_handles_unmapped_motivations(
    stix_intrusion_set: Any,
) -> None:
    """Check if STIX intrusion set handles unmapped motivations."""
    assert stix_intrusion_set is not None  # noqa: S101
    assert (  # noqa: S101
        stix_intrusion_set.primary_motivation.value == "Unknown Motivation"
    )


# Then STIX intrusion set handles empty collections
def _then_stix_intrusion_set_handles_empty_collections(stix_intrusion_set: Any) -> None:
    """Check if STIX intrusion set handles empty collections gracefully."""
    assert stix_intrusion_set is not None  # noqa: S101
    assert stix_intrusion_set.aliases is None  # noqa: S101

    assert stix_intrusion_set.primary_motivation is None  # noqa: S101
    assert stix_intrusion_set.secondary_motivations is None  # noqa: S101


# Scenario: Test extract aliases method
def test_extract_aliases() -> None:
    """Test extracting aliases from threat actor attributes."""
    # Given threat actor attributes with aliases
    attributes = ThreatActorModelFactory.build(
        alt_names_details=[
            AltNameDetailFactory.build(value="APT Example"),
            AltNameDetailFactory.build(value="Example Group"),
        ]
    )
    # When extracting aliases
    aliases = _when_extract_aliases(attributes)
    # Then aliases should be extracted correctly
    _then_aliases_extracted_correctly(aliases, ["APT Example", "Example Group"])


# Scenario: Test extract aliases with empty collection
def test_extract_aliases_empty() -> None:
    """Test extracting aliases with empty collection."""
    # Given threat actor attributes without aliases
    attributes = ThreatActorModelFactory.build(alt_names_details=None)
    # When extracting aliases
    aliases = _when_extract_aliases(attributes)
    # Then aliases should be None
    _then_aliases_are_none(aliases)


# Scenario: Test extract seen dates method
def test_extract_seen_dates() -> None:
    """Test extracting seen dates from threat actor attributes."""
    # Given threat actor attributes with seen dates
    attributes = ThreatActorModelFactory.build(
        first_seen_details=[SeenDetailFactory.build(value="2023-01-01T00:00:00Z")],
        last_seen_details=[SeenDetailFactory.build(value="2023-12-31T23:59:59Z")],
    )
    # When extracting seen dates
    first_seen, last_seen = _when_extract_seen_dates(attributes)
    # Then seen dates should be extracted correctly
    _then_seen_dates_extracted_correctly(first_seen, last_seen)


# Scenario: Test extract motivations method
def test_extract_motivations() -> None:
    """Test extracting motivations from threat actor attributes."""
    # Given threat actor attributes with motivations
    threat_actor = GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(
            motivations=[
                MotivationFactory.build(value="Financial"),
                MotivationFactory.build(value="Corporate Espionage"),
            ]
        )
    )
    mock_org = Identity(
        id=f"identity--{uuid4()}", name="Test", identity_class="organization"
    )
    mock_tlp = MarkingDefinition(
        id=f"marking-definition--{uuid4()}",
        definition_type="statement",
        definition={"statement": "test"},
    )
    mapper = GTIThreatActorToSTIXIntrusionSet(threat_actor, mock_org, mock_tlp)

    # When extracting motivations
    primary, secondary = _when_extract_motivations(mapper, threat_actor.attributes)
    # Then motivations should be extracted correctly with open vocabulary
    _then_motivations_extracted_correctly(
        primary, secondary, "Financial", ["Corporate Espionage"]
    )


# =====================
# Additional GWT Helper Functions
# =====================


# When extract aliases
def _when_extract_aliases(attributes: ThreatActorModel) -> Optional[List[str]]:
    """Extract aliases from threat actor attributes."""
    return GTIThreatActorToSTIXIntrusionSet._extract_aliases(attributes)


# When extract seen dates
def _when_extract_seen_dates(
    attributes: ThreatActorModel,
) -> tuple[Optional[datetime], Optional[datetime]]:
    """Extract seen dates from threat actor attributes."""
    return GTIThreatActorToSTIXIntrusionSet._extract_seen_dates(attributes)


# When extract motivations
def _when_extract_motivations(
    mapper: GTIThreatActorToSTIXIntrusionSet, attributes: ThreatActorModel
) -> tuple[Optional[str], Optional[List[str]]]:
    """Extract motivations from threat actor attributes."""
    return mapper._extract_motivations(attributes)


# Then aliases extracted correctly
def _then_aliases_extracted_correctly(
    aliases: Optional[List[str]], expected: List[str]
) -> None:
    """Check if aliases were extracted correctly."""
    assert aliases is not None  # noqa: S101
    assert len(aliases) == len(expected)  # noqa: S101
    for expected_alias in expected:
        assert expected_alias in aliases  # noqa: S101


# Then aliases are None
def _then_aliases_are_none(aliases: Optional[List[str]]) -> None:
    """Check if aliases are None."""
    assert aliases is None  # noqa: S101


# Then seen dates extracted correctly
def _then_seen_dates_extracted_correctly(
    first_seen: Optional[datetime], last_seen: Optional[datetime]
) -> None:
    """Check if seen dates were extracted correctly."""
    assert first_seen is not None  # noqa: S101
    assert last_seen is not None  # noqa: S101
    assert isinstance(first_seen, datetime)  # noqa: S101
    assert isinstance(last_seen, datetime)  # noqa: S101
    assert first_seen.year == 2023  # noqa: S101
    assert last_seen.year == 2023  # noqa: S101


# Then motivations extracted correctly
def _then_motivations_extracted_correctly(
    primary: Optional[str],
    secondary: Optional[List[str]],
    expected_primary: str,
    expected_secondary: List[str],
) -> None:
    """Check if motivations were extracted correctly."""
    assert primary.value == expected_primary  # noqa: S101
    assert secondary is not None  # noqa: S101
    assert len(secondary) == len(expected_secondary)  # noqa: S101
    secondary_values = [m.value for m in secondary]
    for expected_sec in expected_secondary:
        assert expected_sec in secondary_values  # noqa: S101


# Scenario: Test threat actor with missing hasattr conditions
def test_threat_actor_missing_hasattr() -> None:
    """Test threat actor without hasattr conditions."""
    # Given a threat actor object without attributes property
    threat_actor = GTIThreatActorDataFactory.build()
    delattr(threat_actor, "attributes")

    mock_org = Identity(
        id=f"identity--{uuid4()}", name="Test", identity_class="organization"
    )
    mock_tlp = MarkingDefinition(
        id=f"marking-definition--{uuid4()}",
        definition_type="statement",
        definition={"statement": "test"},
    )
    mapper = GTIThreatActorToSTIXIntrusionSet(threat_actor, mock_org, mock_tlp)

    # When converting to STIX
    # Then should raise ValueError
    _when_convert_to_stix_raises_error(
        mapper, ValueError, "Invalid GTI threat actor data"
    )


# Scenario: Test edge case with empty string values
def test_threat_actor_empty_string_values(
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test handling threat actor with empty string values."""
    # Given a threat actor with empty string values
    threat_actor = GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(
            alt_names_details=[AltNameDetailFactory.build(value="")],
            tags_details=[TagDetailFactory.build(value="")],
            motivations=[MotivationFactory.build(value="")],
        )
    )

    # When converting to STIX
    mapper = _given_gti_threat_actor_mapper(
        threat_actor, mock_organization, mock_tlp_marking
    )
    stix_intrusion_set = _when_convert_to_stix(mapper)

    # Then should handle empty strings gracefully
    assert stix_intrusion_set is not None  # noqa: S101
    assert stix_intrusion_set.aliases is None  # noqa: S101
    assert stix_intrusion_set.labels is None  # noqa: S101


# Scenario: Test unicode characters in threat actor data
def test_threat_actor_unicode_characters(
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test handling threat actor with unicode characters."""
    # Given a threat actor with unicode characters
    threat_actor = GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(
            name="🔥 Unicode Threat Actor 测试",
            description="Threat actor with émojis and spécial charactérs: αβγδε",
            alt_names_details=[AltNameDetailFactory.build(value="APT 测试 🔥")],
        )
    )

    # When converting to STIX
    mapper = _given_gti_threat_actor_mapper(
        threat_actor, mock_organization, mock_tlp_marking
    )
    stix_intrusion_set = _when_convert_to_stix(mapper)

    # Then should preserve unicode characters
    assert stix_intrusion_set.name == "🔥 Unicode Threat Actor 测试"  # noqa: S101
    assert (  # noqa: S101
        stix_intrusion_set.description
        == "Threat actor with émojis and spécial charactérs: αβγδε"
    )
    assert "APT 测试 🔥" in stix_intrusion_set.aliases  # noqa: S101


# Scenario: Test very long strings
def test_threat_actor_long_strings(
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test handling threat actor with very long strings."""
    # Given a threat actor with very long strings
    long_string = "A" * 10000  # 10K characters
    threat_actor = GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(
            name=long_string,
            description=long_string,
        )
    )

    # When converting to STIX
    mapper = _given_gti_threat_actor_mapper(
        threat_actor, mock_organization, mock_tlp_marking
    )
    stix_intrusion_set = _when_convert_to_stix(mapper)

    # Then should handle long strings without truncation
    assert len(stix_intrusion_set.name) == 10000  # noqa: S101
    assert len(stix_intrusion_set.description) == 10000  # noqa: S101


# Scenario: Test boundary timestamp values
@pytest.mark.parametrize(
    "creation_date,modification_date",
    [
        (0, 1),  # Epoch start
        (1672531200, 1672617600),  # Normal dates
        (2147483647, 2147483647),  # 32-bit max timestamp
    ],
)
def test_threat_actor_boundary_timestamps(
    creation_date: int,
    modification_date: int,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test handling threat actor with boundary timestamp values."""
    # Given a threat actor with boundary timestamps
    threat_actor = GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(
            creation_date=creation_date,
            last_modification_date=modification_date,
        )
    )

    # When converting to STIX
    mapper = _given_gti_threat_actor_mapper(
        threat_actor, mock_organization, mock_tlp_marking
    )
    stix_intrusion_set = _when_convert_to_stix(mapper)

    # Then should handle boundary timestamps
    expected_created = datetime.fromtimestamp(creation_date)
    expected_modified = datetime.fromtimestamp(modification_date)
    assert stix_intrusion_set.created == expected_created  # noqa: S101
    assert stix_intrusion_set.modified == expected_modified  # noqa: S101
