"""Tests that GTISoftwareToolkitToSTIXComposite relationships have no template description."""

from uuid import uuid4

import pytest
from connector.src.custom.mappers.gti_software_toolkits.gti_software_toolkit_to_stix_composite import (
    GTISoftwareToolkitToSTIXComposite,
)
from connector.src.custom.models.gti.gti_software_toolkit_model import (
    GTISoftwareToolkitData,
    SoftwareToolkitModel,
    SourceRegion,
    TargetedIndustry,
    TargetedRegion,
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


class SoftwareToolkitModelFactory(ModelFactory[SoftwareToolkitModel]):
    """Factory for SoftwareToolkitModel."""

    __model__ = SoftwareToolkitModel
    creation_date = 1672531200
    last_modification_date = 1672617600


class GTISoftwareToolkitDataFactory(ModelFactory[GTISoftwareToolkitData]):
    """Factory for GTISoftwareToolkitData."""

    __model__ = GTISoftwareToolkitData
    type = "collection"
    attributes = Use(SoftwareToolkitModelFactory.build)


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
def toolkit_with_regions_and_sectors() -> GTISoftwareToolkitData:
    """Software toolkit with one targeted region, one source region, and one sector."""
    return GTISoftwareToolkitDataFactory.build(
        attributes=SoftwareToolkitModelFactory.build(
            name="TOOLKIT-TEST",
            creation_date=1672531200,
            last_modification_date=1672617600,
            targeted_regions_hierarchy=[
                TargetedRegionFactory.build(
                    country="Japan",
                    country_iso2="JP",
                    region="East Asia",
                    first_seen=1672531200,
                    last_seen=1685577600,
                ),
            ],
            source_regions_hierarchy=[
                SourceRegionFactory.build(
                    country="North Korea",
                    country_iso2="KP",
                    region="East Asia",
                    first_seen=1654041600,
                    last_seen=1672531200,
                ),
            ],
            targeted_industries_tree=[
                TargetedIndustryFactory.build(
                    industry="Energy",
                    industry_group="Utilities",
                    first_seen=1672531200,
                    last_seen=1685577600,
                ),
            ],
        ),
    )


@pytest.fixture
def toolkit_with_no_regions_or_sectors() -> GTISoftwareToolkitData:
    """Software toolkit with no regions or sectors."""
    return GTISoftwareToolkitDataFactory.build(
        attributes=SoftwareToolkitModelFactory.build(
            name="TOOLKIT-EMPTY",
            creation_date=1672531200,
            last_modification_date=1672617600,
            targeted_regions_hierarchy=None,
            source_regions_hierarchy=None,
            targeted_industries_tree=None,
        ),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _given_composite_mapper(
    software_toolkit: GTISoftwareToolkitData,
    organization: Identity,
    tlp_marking: MarkingDefinition,
) -> GTISoftwareToolkitToSTIXComposite:
    return GTISoftwareToolkitToSTIXComposite(
        software_toolkit=software_toolkit,
        organization=organization,
        tlp_marking=tlp_marking,
    )


def _when_convert_to_stix(mapper: GTISoftwareToolkitToSTIXComposite) -> list:
    return mapper.to_stix()


def _then_relationship_has_no_description(relationship) -> None:  # noqa: ANN001
    assert relationship.relationship_type is not None  # noqa: S101
    assert relationship.description is None  # noqa: S101


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.order(1)
def test_composite_returns_tool_location_sector_and_relationships(
    toolkit_with_regions_and_sectors,
    mock_organization,
    mock_tlp_marking,
):
    """The composite should return locations, sectors, tool, and relationships."""
    mapper = _given_composite_mapper(
        toolkit_with_regions_and_sectors,
        mock_organization,
        mock_tlp_marking,
    )

    stix_objects = _when_convert_to_stix(mapper)

    types = [obj.type for obj in stix_objects if hasattr(obj, "type")]
    assert "location" in types  # noqa: S101
    assert "identity" in types  # noqa: S101
    assert "tool" in types  # noqa: S101
    assert "relationship" in types  # noqa: S101


@pytest.mark.order(1)
def test_targets_location_relationship_has_no_description(
    toolkit_with_regions_and_sectors,
    mock_organization,
    mock_tlp_marking,
):
    """The 'targets' (location) relationship must have description=None."""
    mapper = _given_composite_mapper(
        toolkit_with_regions_and_sectors,
        mock_organization,
        mock_tlp_marking,
    )

    stix_objects = _when_convert_to_stix(mapper)

    targets_location_rels = [
        obj
        for obj in stix_objects
        if hasattr(obj, "relationship_type")
        and obj.relationship_type == "targets"
        and any(
            loc.name == "Japan"
            for loc in stix_objects
            if hasattr(loc, "type")
            and loc.type == "location"
            and obj.target_ref == loc.id
        )
    ]
    assert len(targets_location_rels) >= 1  # noqa: S101
    for rel in targets_location_rels:
        _then_relationship_has_no_description(rel)


@pytest.mark.order(1)
def test_originates_from_location_relationship_has_no_description(
    toolkit_with_regions_and_sectors,
    mock_organization,
    mock_tlp_marking,
):
    """The 'originates-from' (location) relationship must have description=None."""
    mapper = _given_composite_mapper(
        toolkit_with_regions_and_sectors,
        mock_organization,
        mock_tlp_marking,
    )

    stix_objects = _when_convert_to_stix(mapper)

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
    toolkit_with_regions_and_sectors,
    mock_organization,
    mock_tlp_marking,
):
    """The 'targets' (sector/identity) relationship must have description=None."""
    mapper = _given_composite_mapper(
        toolkit_with_regions_and_sectors,
        mock_organization,
        mock_tlp_marking,
    )

    stix_objects = _when_convert_to_stix(mapper)

    locations = [
        obj for obj in stix_objects if hasattr(obj, "type") and obj.type == "location"
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


@pytest.mark.order(1)
def test_composite_with_no_regions_or_sectors_returns_only_tool(
    toolkit_with_no_regions_or_sectors,
    mock_organization,
    mock_tlp_marking,
):
    """When no regions or sectors exist, the composite should return only the tool."""
    mapper = _given_composite_mapper(
        toolkit_with_no_regions_or_sectors,
        mock_organization,
        mock_tlp_marking,
    )

    stix_objects = _when_convert_to_stix(mapper)

    types = [obj.type for obj in stix_objects if hasattr(obj, "type")]
    assert "tool" in types  # noqa: S101
    assert "relationship" not in types  # noqa: S101
    assert "location" not in types  # noqa: S101
    assert "identity" not in types  # noqa: S101
