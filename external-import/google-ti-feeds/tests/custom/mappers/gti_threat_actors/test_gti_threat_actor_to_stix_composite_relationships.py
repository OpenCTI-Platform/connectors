"""Tests that GTIThreatActorToSTIXComposite relationships have no template description."""

from uuid import uuid4

import pytest
from connector.src.custom.mappers.gti_threat_actors.gti_threat_actor_to_stix_composite import (
    GTIThreatActorToSTIXComposite,
)
from connector.src.custom.models.gti.gti_threat_actor_model import (
    GTIThreatActorData,
    SourceRegion,
    TargetedIndustry,
    TargetedRegion,
    ThreatActorModel,
)
from polyfactory.factories.pydantic_factory import ModelFactory
from polyfactory.fields import Use
from stix2.v21 import Identity, MarkingDefinition  # type: ignore

# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------


class SourceRegionFactory(ModelFactory[SourceRegion]):
    """Factory for SourceRegion model."""

    __model__ = SourceRegion


class TargetedRegionFactory(ModelFactory[TargetedRegion]):
    """Factory for TargetedRegion model."""

    __model__ = TargetedRegion


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


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_organization():
    """Mock organization Identity object."""
    return Identity(  # pylint: disable=W9101
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
def threat_actor_with_regions_and_sectors() -> GTIThreatActorData:
    """Threat actor with one targeted region, one source region, and one sector."""
    return GTIThreatActorDataFactory.build(
        attributes=ThreatActorModelFactory.build(
            name="APT-TEST",
            creation_date=1672531200,
            last_modification_date=1672617600,
            targeted_regions_hierarchy=[
                TargetedRegionFactory.build(
                    country="United States",
                    country_iso2="US",
                    region="North America",
                    first_seen=1672531200,
                    last_seen=1685577600,
                ),
            ],
            source_regions_hierarchy=[
                SourceRegionFactory.build(
                    country="Russia",
                    country_iso2="RU",
                    region="Eastern Europe",
                    first_seen=1654041600,
                    last_seen=1672531200,
                ),
            ],
            targeted_industries_tree=[
                TargetedIndustryFactory.build(
                    industry="Finance",
                    industry_group="Financial Services",
                    first_seen=1672531200,
                    last_seen=1685577600,
                ),
            ],
        ),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _given_composite_mapper(
    threat_actor: GTIThreatActorData,
    organization: Identity,
    tlp_marking: MarkingDefinition,
) -> GTIThreatActorToSTIXComposite:
    return GTIThreatActorToSTIXComposite(
        threat_actor=threat_actor,
        organization=organization,
        tlp_marking=tlp_marking,
    )


def _when_convert_to_stix(mapper: GTIThreatActorToSTIXComposite) -> list:
    return mapper.to_stix()


def _then_relationship_has_no_description(relationship) -> None:  # noqa: ANN001
    assert relationship.relationship_type is not None  # noqa: S101
    assert relationship.description is None  # noqa: S101


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.order(1)
def test_targets_location_relationship_has_no_description(
    threat_actor_with_regions_and_sectors,
    mock_organization,
    mock_tlp_marking,
):
    """The 'targets' (location) relationship must have description=None."""
    # GIVEN
    mapper = _given_composite_mapper(
        threat_actor_with_regions_and_sectors,
        mock_organization,
        mock_tlp_marking,
    )

    # WHEN
    stix_objects = _when_convert_to_stix(mapper)

    # THEN
    targets_location_rels = [
        obj
        for obj in stix_objects
        if hasattr(obj, "relationship_type")
        and obj.relationship_type == "targets"
        and any(
            loc.name == "United States"
            for loc in stix_objects
            if hasattr(loc, "name")
            and hasattr(loc, "country")
            and obj.target_ref == loc.id
        )
    ]
    assert len(targets_location_rels) >= 1  # noqa: S101
    for rel in targets_location_rels:
        _then_relationship_has_no_description(rel)


@pytest.mark.order(1)
def test_originates_from_location_relationship_has_no_description(
    threat_actor_with_regions_and_sectors,
    mock_organization,
    mock_tlp_marking,
):
    """The 'originates-from' (location) relationship must have description=None."""
    # GIVEN
    mapper = _given_composite_mapper(
        threat_actor_with_regions_and_sectors,
        mock_organization,
        mock_tlp_marking,
    )

    # WHEN
    stix_objects = _when_convert_to_stix(mapper)

    # THEN
    originates_rels = [
        obj
        for obj in stix_objects
        if hasattr(obj, "relationship_type")
        and obj.relationship_type == "originates-from"
    ]
    assert len(originates_rels) >= 1  # noqa: S101
    for rel in originates_rels:
        _then_relationship_has_no_description(rel)


@pytest.mark.order(1)
def test_targets_sector_relationship_has_no_description(
    threat_actor_with_regions_and_sectors,
    mock_organization,
    mock_tlp_marking,
):
    """The 'targets' (sector/identity) relationship must have description=None."""
    # GIVEN
    mapper = _given_composite_mapper(
        threat_actor_with_regions_and_sectors,
        mock_organization,
        mock_tlp_marking,
    )

    # WHEN
    stix_objects = _when_convert_to_stix(mapper)

    # THEN — sectors are Identity objects; their relationships are "targets" pointing at identity ids
    locations = [
        obj
        for obj in stix_objects
        if hasattr(obj, "country") or (hasattr(obj, "type") and obj.type == "location")
    ]
    location_ids = {loc.id for loc in locations}

    targets_sector_rels = [
        obj
        for obj in stix_objects
        if hasattr(obj, "relationship_type")
        and obj.relationship_type == "targets"
        and obj.target_ref not in location_ids
    ]
    assert len(targets_sector_rels) >= 1  # noqa: S101
    for rel in targets_sector_rels:
        _then_relationship_has_no_description(rel)
