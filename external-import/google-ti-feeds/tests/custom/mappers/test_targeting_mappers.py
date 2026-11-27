"""Tests for the location and sector mappers shared by the collections."""

from typing import Any
from uuid import uuid4

import pytest
from connector.src.custom.mappers.gti_campaigns.gti_campaign_to_stix_identity import (
    GTICampaignToSTIXIdentity,
)
from connector.src.custom.mappers.gti_threat_actors.gti_threat_actor_to_stix_composite import (
    GTIThreatActorToSTIXComposite,
)
from connector.src.custom.mappers.gti_threat_actors.gti_threat_actor_to_stix_identity import (
    GTIThreatActorToSTIXIdentity,
)
from connector.src.custom.mappers.gti_threat_actors.gti_threat_actor_to_stix_location import (
    GTIThreatActorToSTIXLocation,
)
from connector.src.custom.mappers.targeting_mappers import seen_dates
from connector.src.custom.models.gti.gti_campaign_model import GTICampaignData
from connector.src.custom.models.gti.gti_threat_actor_model import GTIThreatActorData
from stix2.v21 import Identity, MarkingDefinition  # type: ignore

# 2023-01-01, 2023-06-01, 2024-01-01 and 2024-06-01 UTC
JAN_2023, JUN_2023, JAN_2024, JUN_2024 = 1672531200, 1685577600, 1704067200, 1717200000

FINANCE_ENTRIES = [
    {
        "industry_group": "Finance",
        "industry": "Banking",
        "confidence": "confirmed",
        "source": "Mandiant",
        "description": "Retail banks.",
        "first_seen": JUN_2023,
        "last_seen": JAN_2024,
    },
    {
        "industry_group": "Finance",
        "industry": "Insurance",
        "confidence": "suspected",
        "source": "Mandiant",
        "description": "Insurers.",
        "first_seen": JAN_2023,
        "last_seen": JUN_2024,
    },
]


@pytest.fixture
def organization() -> Identity:
    """Return the author identity."""
    return Identity(  # pylint: disable=W9101  # it's a test no real ingest
        name="Test Organization", identity_class="organization"
    )


@pytest.fixture
def marking() -> MarkingDefinition:
    """Return a marking definition."""
    return MarkingDefinition(
        id=f"marking-definition--{uuid4()}",
        definition_type="statement",
        definition={"statement": "Internal Use Only"},
    )


def _threat_actor(**attributes: Any) -> GTIThreatActorData:
    return GTIThreatActorData.model_validate(
        {
            "id": "threat-actor--1",
            "type": "collection",
            "attributes": {
                "name": "APT Example",
                "creation_date": JAN_2023,
                "last_modification_date": JAN_2023,
                "private": False,
                **attributes,
            },
        }
    )


def test_seen_dates() -> None:
    """A last seen date not after the first seen date is dropped."""
    # Given GTI first and last seen timestamps
    # When they are converted
    # Then a stop time before the start time is dropped
    first, last = seen_dates(JAN_2024, JAN_2023)
    assert first is not None and last is None  # noqa: S101
    assert seen_dates(None, None) == (None, None)  # noqa: S101


def test_duplicate_sectors_are_merged(
    organization: Identity, marking: MarkingDefinition
) -> None:
    """A sector listed twice is one sector spanning both entries, keeping their details."""
    # Given a threat actor targeting Finance through two industries
    mapper = GTIThreatActorToSTIXIdentity(
        _threat_actor(targeted_industries_tree=FINANCE_ENTRIES), organization, marking
    )
    # When its sectors are converted
    (finance,) = mapper.to_stix_with_timing()
    # Then the dates span both and every detail is kept
    assert finance.identity.name == "Finance"  # noqa: S101
    assert finance.first_seen == seen_dates(JAN_2023, None)[0]  # noqa: S101
    assert finance.last_seen == seen_dates(JUN_2024, None)[0]  # noqa: S101
    assert finance.confidence == "confirmed; suspected"  # noqa: S101
    assert finance.source == "Mandiant"  # noqa: S101
    assert finance.note == "Banking: Retail banks.; Insurance: Insurers."  # noqa: S101


def test_single_sector_note_has_no_subject(
    organization: Identity, marking: MarkingDefinition
) -> None:
    """A sector listed once keeps the GTI note as is."""
    # Given a threat actor targeting Finance once
    mapper = GTIThreatActorToSTIXIdentity(
        _threat_actor(targeted_industries_tree=FINANCE_ENTRIES[:1]),
        organization,
        marking,
    )
    # When its sectors are converted
    (finance,) = mapper.to_stix_with_timing()
    # Then the note is not prefixed
    assert finance.note == "Retail banks."  # noqa: S101


def test_duplicate_countries_are_merged_per_role(
    organization: Identity, marking: MarkingDefinition
) -> None:
    """A country targeted twice is merged, a source country stays separate."""
    # Given a threat actor targeting France twice and coming from France
    france = {"country": "France", "country_iso2": "FR", "confidence": "confirmed"}
    mapper = GTIThreatActorToSTIXLocation(
        _threat_actor(
            targeted_regions_hierarchy=[
                {**france, "first_seen": JUN_2023},
                {**france, "first_seen": JAN_2023},
            ],
            source_regions_hierarchy=[france],
        ),
        organization,
        marking,
    )
    # When its countries are converted
    countries = mapper.to_stix_with_timing()
    # Then France is targeted once, from the earliest date, and a source once
    assert [(c.is_targeted, c.is_source) for c in countries] == [  # noqa: S101
        (True, False),
        (False, True),
    ]
    assert countries[0].first_seen == seen_dates(JAN_2023, None)[0]  # noqa: S101


def test_one_targets_relationship_per_merged_sector(
    organization: Identity, marking: MarkingDefinition
) -> None:
    """The composite creates one targets relationship for a merged sector."""
    # Given a threat actor targeting Finance through two industries
    mapper = GTIThreatActorToSTIXComposite(
        threat_actor=_threat_actor(targeted_industries_tree=FINANCE_ENTRIES),
        organization=organization,
        tlp_marking=marking,
    )
    # When it is converted
    stix_objects = mapper.to_stix()
    # Then there is one sector and one targets relationship
    targets = [
        obj
        for obj in stix_objects
        if getattr(obj, "relationship_type", None) == "targets"
    ]
    assert [
        obj.name for obj in stix_objects if obj.type == "identity"
    ] == [  # noqa: S101
        "Finance"
    ]
    assert len(targets) == 1  # noqa: S101
    assert targets[0].description == (  # noqa: S101
        "GTI confidence: confirmed; suspected. Source: Mandiant. "
        "Banking: Retail banks.; Insurance: Insurers."
    )


def test_campaign_sectors_follow_the_shared_rules(
    organization: Identity, marking: MarkingDefinition
) -> None:
    """Campaigns merge duplicate sectors and skip industries without group."""
    # Given a campaign with a duplicate sector and an industry without group
    campaign = GTICampaignData.model_validate(
        {
            "id": "campaign--1",
            "type": "collection",
            "attributes": {
                "name": "Campaign",
                "creation_date": JAN_2023,
                "last_modification_date": JAN_2023,
                "targeted_industries_tree": [
                    *FINANCE_ENTRIES,
                    {"industry_group": "", "industry": "Banking", "confidence": "x"},
                ],
            },
        }
    )
    mapper = GTICampaignToSTIXIdentity(campaign, organization, marking)
    # When its sectors are converted
    # Then only Finance remains
    assert [s.name for s in mapper.to_stix()] == ["Finance"]  # noqa: S101
