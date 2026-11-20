"""Tests for adding the CrowdStrike author identity to a STIX bundle."""

import json
from datetime import UTC, datetime
from typing import Any
from unittest import mock

import pytest
import stix2
from conftest import load_fixture, make_indicator
from crowdstrike_indicators.entities.models import CrowdStrikeIndicator
from crowdstrike_indicators.transform.step01_create_indicator import (
    CreateCrowdStrikeIndicator,
)
from crowdstrike_indicators.transform.step02_add_malware import CrowdStrikeAddMalware
from crowdstrike_indicators.transform.step03_add_attack_patterns import (
    AttackPatternCatalog,
    CrowdStrikeAddAttackPatterns,
)
from crowdstrike_indicators.transform.step04_make_bundle import (
    MakeStixBundle,
    missing_references,
)
from crowdstrike_indicators.transform.step05_add_identity import (
    CrowdStrikeAddIdentity,
    author_identity,
    identity_id,
)

from shared.errors import ItemConversionError

SAMPLE_ROWS = load_fixture("indicators_sample.json")["resources"]
SAMPLE_IDS = [f"{row['type']}-{i}" for i, row in enumerate(SAMPLE_ROWS)]
DOMAIN_7 = next(row for row in SAMPLE_ROWS if row["id"] == "domain_malicious-7.example")
CATALOG = AttackPatternCatalog(load_fixture("attack_extract.json"))

# The id pycti's Identity.generate_id("CrowdStrike", "organization") gives,
# that is the author id of the existing CrowdStrike connector.
CROWDSTRIKE_IDENTITY_ID = "identity--f29f12ba-3980-5642-9b3e-d11e9b296aed"
OTHER_AUTHOR = "identity--00000000-0000-5000-8000-000000000001"


def chain(raw: dict[str, Any]) -> stix2.v21.Bundle:
    """Run the steps before ``CrowdStrikeAddIdentity``."""
    indicator = CreateCrowdStrikeIndicator().convert(
        CrowdStrikeIndicator.model_validate(raw)
    )
    bundle = CrowdStrikeAddMalware().convert(indicator)
    bundle = CrowdStrikeAddAttackPatterns(CATALOG).convert(bundle)
    return MakeStixBundle().convert(bundle)


def add(bundle: stix2.v21.Bundle) -> stix2.v21.Bundle:
    return CrowdStrikeAddIdentity().convert(bundle)


def without(obj: Any, name: str) -> dict[str, Any]:
    serialized = json.loads(obj.serialize())
    serialized.pop(name, None)
    return serialized


# --- Identity ----------------------------------------------------------------


def test_identity_is_the_crowdstrike_organization():
    identity = author_identity()

    assert identity.type == "identity"
    assert identity.id == CROWDSTRIKE_IDENTITY_ID
    assert identity.name == "CrowdStrike"
    assert identity.identity_class == "organization"
    assert "created_by_ref" not in identity


def test_identity_dates_are_fixed():
    result = add(chain(DOMAIN_7))

    identity = json.loads(result.objects[0].serialize())
    assert identity["created"] == "1970-01-01T00:00:00.000Z"
    assert identity["modified"] == "1970-01-01T00:00:00.000Z"


@pytest.mark.parametrize(
    "name", ["CrowdStrike", "crowdstrike", "  CROWDSTRIKE ", "CrowdStrike\n"]
)
def test_identity_id_ignores_case_and_surrounding_spaces(name):
    assert identity_id(name, "Organization") == CROWDSTRIKE_IDENTITY_ID


def test_identity_id_depends_on_the_class():
    assert identity_id("CrowdStrike", "individual") != CROWDSTRIKE_IDENTITY_ID


# --- Objects -----------------------------------------------------------------


@pytest.mark.parametrize("raw", SAMPLE_ROWS, ids=SAMPLE_IDS)
def test_identity_first_then_every_object_in_order(raw):
    bundle = chain(raw)

    result = add(bundle)

    assert result.type == "bundle"
    assert result.id == bundle.id
    assert [obj.id for obj in result.objects] == [
        CROWDSTRIKE_IDENTITY_ID,
        *(obj.id for obj in bundle.objects),
    ]


@pytest.mark.parametrize("raw", SAMPLE_ROWS, ids=SAMPLE_IDS)
def test_every_object_is_created_by_the_identity(raw):
    result = add(chain(raw))

    assert all(
        obj.created_by_ref == CROWDSTRIKE_IDENTITY_ID for obj in result.objects[1:]
    )


@pytest.mark.parametrize("raw", SAMPLE_ROWS, ids=SAMPLE_IDS)
def test_nothing_else_changes(raw):
    bundle = chain(raw)

    result = add(bundle)

    for before, after in zip(bundle.objects, result.objects[1:], strict=True):
        assert type(after) is type(before)
        assert without(after, "created_by_ref") == json.loads(before.serialize())


def test_input_bundle_is_left_unchanged():
    bundle = chain(SAMPLE_ROWS[0])
    serialized = bundle.serialize()

    add(bundle)

    assert bundle.serialize() == serialized
    assert all("created_by_ref" not in obj for obj in bundle.objects)


def test_custom_properties_are_kept():
    result = add(chain(DOMAIN_7))

    parsed = stix2.parse(result.serialize(), allow_custom=True)

    indicator = parsed.objects[1]
    assert indicator.created_by_ref == CROWDSTRIKE_IDENTITY_ID
    assert indicator["x_crowdstrike_marker"] == DOMAIN_7["_marker"]
    assert indicator["x_crowdstrike_malware_families"] == DOMAIN_7["malware_families"]


def test_undeclared_custom_properties_are_kept():
    parsed = stix2.parse(chain(make_indicator(1)).serialize(), allow_custom=True)
    assert parsed.objects[0].has_custom

    result = add(parsed)

    assert result.objects[1]["x_crowdstrike_marker"] == "1700000001x000001"
    assert result.objects[1].created_by_ref == CROWDSTRIKE_IDENTITY_ID


def test_existing_author_is_kept():
    malware = stix2.v21.Malware(
        name="A", is_family=True, created_by_ref=OTHER_AUTHOR, allow_custom=True
    )
    bundle = stix2.v21.Bundle(objects=[malware])

    result = add(bundle)

    assert result.objects[1] is malware


def test_identity_is_not_repeated():
    once = add(chain(DOMAIN_7))

    twice = add(once)

    assert [obj.id for obj in twice.objects] == [obj.id for obj in once.objects]
    assert twice.serialize() == once.serialize()


def test_empty_bundle_gets_the_identity_only():
    result = add(stix2.v21.Bundle())

    assert [obj.id for obj in result.objects] == [CROWDSTRIKE_IDENTITY_ID]


# --- References --------------------------------------------------------------


@pytest.mark.parametrize("raw", SAMPLE_ROWS, ids=SAMPLE_IDS)
def test_no_missing_reference(raw):
    assert missing_references(add(chain(raw)).objects) == []


# --- Errors ------------------------------------------------------------------


def test_object_without_created_by_ref_raises_conversion_error():
    # STIX cyber-observables have no created_by_ref property.
    bundle = stix2.v21.Bundle(objects=[stix2.v21.DomainName(value="a.example")])

    with pytest.raises(ItemConversionError) as caught:
        add(bundle)

    assert caught.value.item_id == bundle.id
    assert "created_by_ref" in str(caught.value)


# --- Determinism -------------------------------------------------------------


def test_same_input_same_output_whatever_the_time():
    bundle = chain(SAMPLE_ROWS[0])
    first = add(bundle)

    later = datetime(2099, 1, 1, tzinfo=UTC)
    with mock.patch("stix2.base.get_timestamp", return_value=later):
        second = add(bundle)

    assert first.serialize() == second.serialize()
