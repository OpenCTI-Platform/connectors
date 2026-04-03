"""Tests that GTICampaignToSTIXComposite relationships have no template description."""

from uuid import uuid4

import pytest
from connector.src.custom.mappers.gti_campaigns.gti_campaign_to_stix_composite import (
    GTICampaignToSTIXComposite,
)
from connector.src.custom.models.gti.gti_campaign_model import (
    CampaignModel,
    GTICampaignData,
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


class CampaignModelFactory(ModelFactory[CampaignModel]):
    """Factory for CampaignModel."""

    __model__ = CampaignModel


class GTICampaignDataFactory(ModelFactory[GTICampaignData]):
    """Factory for GTICampaignData."""

    __model__ = GTICampaignData
    type = "campaign"
    attributes = Use(CampaignModelFactory.build)


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
def campaign_with_regions_and_industries() -> GTICampaignData:
    """Campaign with one targeted region, one source region, and one identity/industry."""
    return GTICampaignDataFactory.build(
        attributes=CampaignModelFactory.build(
            name="CAMPAIGN-TEST",
            creation_date=1672531200,
            last_modification_date=1672617600,
            targeted_regions_hierarchy=[
                TargetedRegionFactory.build(
                    country="Germany",
                    country_iso2="DE",
                    region="Western Europe",
                    first_seen=1672531200,
                    last_seen=1685577600,
                ),
            ],
            source_regions_hierarchy=[
                SourceRegionFactory.build(
                    country="China",
                    country_iso2="CN",
                    region="East Asia",
                    first_seen=1654041600,
                    last_seen=1672531200,
                ),
            ],
            targeted_industries_tree=[
                TargetedIndustryFactory.build(
                    industry="Technology",
                    industry_group="Information Technology",
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
    campaign: GTICampaignData,
    organization: Identity,
    tlp_marking: MarkingDefinition,
) -> GTICampaignToSTIXComposite:
    return GTICampaignToSTIXComposite(
        campaign=campaign,
        organization=organization,
        tlp_marking=tlp_marking,
    )


def _when_convert_to_stix(mapper: GTICampaignToSTIXComposite) -> list:
    return mapper.to_stix()


def _then_relationship_has_no_description(relationship) -> None:  # noqa: ANN001
    assert relationship.relationship_type is not None  # noqa: S101
    assert relationship.description is None  # noqa: S101


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.order(1)
def test_targets_location_relationship_has_no_description(
    campaign_with_regions_and_industries,
    mock_organization,
    mock_tlp_marking,
):
    """The 'targets' (location) relationship must have description=None."""
    # GIVEN
    mapper = _given_composite_mapper(
        campaign_with_regions_and_industries,
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
            loc.name == "Germany"
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
    campaign_with_regions_and_industries,
    mock_organization,
    mock_tlp_marking,
):
    """The 'originates-from' (location) relationship must have description=None."""
    # GIVEN
    mapper = _given_composite_mapper(
        campaign_with_regions_and_industries,
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
def test_targets_industry_relationship_has_no_description(
    campaign_with_regions_and_industries,
    mock_organization,
    mock_tlp_marking,
):
    """The 'targets' (identity/industry) relationship must have description=None."""
    # GIVEN
    mapper = _given_composite_mapper(
        campaign_with_regions_and_industries,
        mock_organization,
        mock_tlp_marking,
    )

    # WHEN
    stix_objects = _when_convert_to_stix(mapper)

    # THEN — industries are Identity objects; filter out location targets
    locations = [
        obj for obj in stix_objects if hasattr(obj, "type") and obj.type == "location"
    ]
    location_ids = {loc.id for loc in locations}

    targets_industry_rels = [
        obj
        for obj in stix_objects
        if hasattr(obj, "relationship_type")
        and obj.relationship_type == "targets"
        and obj.target_ref not in location_ids
    ]
    assert len(targets_industry_rels) >= 1  # noqa: S101
    for rel in targets_industry_rels:
        _then_relationship_has_no_description(rel)
