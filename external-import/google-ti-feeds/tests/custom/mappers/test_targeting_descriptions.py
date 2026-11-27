"""Tests for the GTI confidence, source and note of targets relationships."""

from collections.abc import Iterator
from typing import Any
from uuid import uuid4

import pytest
from connector.src.custom.mappers.gti_threat_actors.gti_threat_actor_to_stix_composite import (
    GTIThreatActorToSTIXComposite,
)
from connector.src.custom.mappers.relationship_reasons import (
    set_relationship_descriptions,
    targeting_reason,
)
from connector.src.custom.mappers.timing_models import LocationWithTiming
from connector.src.custom.models.gti.gti_threat_actor_model import GTIThreatActorData
from connector.src.stix.octi.models.intrusion_set_model import OctiIntrusionSetModel
from pycti import Location as PyctiLocation  # type: ignore[import-untyped]
from stix2.v21 import Identity, Location, MarkingDefinition  # type: ignore

NOTE = "Targeted government ministries."
FRANCE = Location(
    id=PyctiLocation.generate_id("France", "Country"),
    name="France",
    country="FR",
    custom_properties={"x_opencti_location_type": "Country"},
    allow_custom=True,
)


@pytest.fixture(autouse=True)
def default_descriptions() -> Iterator[None]:
    """Restore the default (disabled) relationship descriptions after each test."""
    yield
    set_relationship_descriptions(False)


def _timing(**fields: Any) -> LocationWithTiming:
    return LocationWithTiming(location=FRANCE, is_targeted=True, **fields)


@pytest.mark.parametrize(
    "fields, expected",
    [
        (
            {"confidence": "confirmed", "source": "Mandiant", "note": f" {NOTE} "},
            f"GTI confidence: confirmed. Source: Mandiant. {NOTE}",
        ),
        ({"note": NOTE}, NOTE),
        ({}, None),
    ],
)
def test_targeting_reason_without_option(
    fields: dict[str, str], expected: str | None
) -> None:
    """By default, only the GTI confidence, source and note are written."""
    # Given a targeted country with GTI details
    intrusion_set = Identity(  # pylint: disable=W9101  # it's a test no real ingest
        name="unused", identity_class="organization"
    )
    # When the description is built
    # Then it holds GTI content only, or nothing
    assert (  # noqa: S101
        targeting_reason(intrusion_set, "targets", FRANCE, _timing(**fields))
        == expected
    )


def test_targeting_reason_with_option() -> None:
    """With the option, the GTI list the target comes from is stated first."""
    # Given relationship descriptions enabled
    set_relationship_descriptions(True)
    intrusion_set = OctiIntrusionSetModel.create(
        name="APT Example", organization_id=f"identity--{uuid4()}", marking_ids=[]
    )
    # When the description is built
    description = targeting_reason(
        intrusion_set,
        "targets",
        FRANCE,
        _timing(confidence="confirmed", source="Mandiant", note=NOTE),
    )
    # Then it states the GTI list, confidence, source and note
    assert description == (  # noqa: S101
        "Stated by GTI: GTI lists the country 'France' among the targeted regions "
        "of the intrusion set 'APT Example', with confidence 'confirmed', source "
        f"'Mandiant'. GTI note: {NOTE}"
    )


def test_threat_actor_note_moves_to_relationship() -> None:
    """The GTI note describes the targets relationship, not the shared country."""
    # Given a threat actor targeting France with a GTI note
    organization = Identity(  # pylint: disable=W9101  # it's a test no real ingest
        name="Test Organization", identity_class="organization"
    )
    marking = MarkingDefinition(
        id=f"marking-definition--{uuid4()}",
        definition_type="statement",
        definition={"statement": "Internal Use Only"},
    )
    threat_actor = GTIThreatActorData.model_validate(
        {
            "id": "threat-actor--1",
            "type": "collection",
            "attributes": {
                "name": "APT Example",
                "creation_date": 1705276800,
                "last_modification_date": 1705276800,
                "private": False,
                "targeted_regions_hierarchy": [
                    {
                        "confidence": "confirmed",
                        "country": "France",
                        "country_iso2": "FR",
                        "description": NOTE,
                        "source": "Mandiant",
                    }
                ],
            },
        }
    )
    mapper = GTIThreatActorToSTIXComposite(
        threat_actor=threat_actor, organization=organization, tlp_marking=marking
    )
    # When it is converted
    stix_objects = mapper.to_stix()
    # Then the note is on the relationship and the country has no description
    country = next(obj for obj in stix_objects if obj.type == "location")
    targets = next(
        obj
        for obj in stix_objects
        if getattr(obj, "relationship_type", None) == "targets"
    )
    assert country.get("description") is None  # noqa: S101
    assert targets.description == (  # noqa: S101
        f"GTI confidence: confirmed. Source: Mandiant. {NOTE}"
    )
