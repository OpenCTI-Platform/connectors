"""Tests for marking a STIX bundle with one TLP level."""

import json
from datetime import UTC, datetime
from typing import Any
from unittest import mock

import pytest
import stix2
from conftest import load_fixture, make_indicator
from crowdstrike_indicators.entities.models import CrowdStrikeIndicator
from crowdstrike_indicators.transform.add_attack_patterns import (
    AttackPatternCatalog,
    CrowdStrikeAddAttackPatterns,
)
from crowdstrike_indicators.transform.add_identity import CrowdStrikeAddIdentity
from crowdstrike_indicators.transform.add_malware import CrowdStrikeAddMalware
from crowdstrike_indicators.transform.add_tlp_marking import (
    MARKING_DEFINITIONS,
    CrowdStrikeAddTlpMarking,
    TLPLevel,
)
from crowdstrike_indicators.transform.create_indicator import CreateCrowdStrikeIndicator
from crowdstrike_indicators.transform.make_bundle import (
    MakeStixBundle,
    missing_references,
)

CLEAR_ID = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
GREEN_ID = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
AMBER_ID = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
AMBER_STRICT_ID = "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"
RED_ID = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"
TLP_DATE = "2017-01-20T00:00:00.000Z"
CROWDSTRIKE_IDENTITY_ID = "identity--f29f12ba-3980-5642-9b3e-d11e9b296aed"
OTHER_MARKING = "marking-definition--00000000-0000-5000-8000-000000000001"

SAMPLE_ROWS = load_fixture("indicators_sample.json")["resources"]
SAMPLE_IDS = [f"{row['type']}-{i}" for i, row in enumerate(SAMPLE_ROWS)]
DOMAIN_7 = next(row for row in SAMPLE_ROWS if row["id"] == "domain_malicious-7.example")
CATALOG = AttackPatternCatalog(load_fixture("attack_extract.json"))


def chain(raw: dict[str, Any]) -> stix2.v21.Bundle:
    """Run the steps before ``CrowdStrikeAddTlpMarking``."""
    indicator = CreateCrowdStrikeIndicator().convert(
        CrowdStrikeIndicator.model_validate(raw)
    )
    bundle = CrowdStrikeAddMalware().convert(indicator)
    bundle = CrowdStrikeAddAttackPatterns(CATALOG).convert(bundle)
    return CrowdStrikeAddIdentity().convert(MakeStixBundle().convert(bundle))


def mark(bundle: stix2.v21.Bundle, level: str = "GREEN") -> stix2.v21.Bundle:
    return CrowdStrikeAddTlpMarking(level).convert(bundle)


def without(obj: Any, name: str) -> dict[str, Any]:
    serialized = json.loads(obj.serialize())
    serialized.pop(name, None)
    return serialized


def marking(level: TLPLevel) -> dict:
    return json.loads(MARKING_DEFINITIONS[level].serialize())


# --- Levels ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "level"),
    [
        ("CLEAR", TLPLevel.CLEAR),
        ("clear", TLPLevel.CLEAR),
        ("WHITE", TLPLevel.CLEAR),
        ("White", TLPLevel.CLEAR),
        ("green", TLPLevel.GREEN),
        ("Amber", TLPLevel.AMBER),
        ("amber+strict", TLPLevel.AMBER_STRICT),
        ("AMBER+STRICT", TLPLevel.AMBER_STRICT),
        ("red", TLPLevel.RED),
        (TLPLevel.RED, TLPLevel.RED),
    ],
)
def test_level_names_are_case_insensitive(value, level):
    assert TLPLevel(value) is level


@pytest.mark.parametrize("value", ["PURPLE", "TLP:AMBER", "AMBER_STRICT", ""])
def test_unknown_level_is_named(value):
    with pytest.raises(ValueError, match=f"'{value}'"):
        TLPLevel(value)


def test_every_level_has_a_marking_definition():
    assert set(MARKING_DEFINITIONS) == set(TLPLevel)


# --- Marking definitions -----------------------------------------------------


@pytest.mark.parametrize(
    ("level", "marking_id", "name", "tlp"),
    [
        (TLPLevel.CLEAR, CLEAR_ID, "TLP:WHITE", "white"),
        (TLPLevel.GREEN, GREEN_ID, "TLP:GREEN", "green"),
        (TLPLevel.AMBER, AMBER_ID, "TLP:AMBER", "amber"),
        (TLPLevel.RED, RED_ID, "TLP:RED", "red"),
    ],
)
def test_standard_tlp_marking_definitions(level, marking_id, name, tlp):
    assert marking(level) == {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": marking_id,
        "created": TLP_DATE,
        "definition_type": "tlp",
        "name": name,
        "definition": {"tlp": tlp},
    }


def test_amber_strict_is_opencti_custom_marking():
    assert marking(TLPLevel.AMBER_STRICT) == {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": AMBER_STRICT_ID,
        "created": TLP_DATE,
        "definition_type": "statement",
        "definition": {"statement": "custom"},
        "x_opencti_definition_type": "TLP",
        "x_opencti_definition": "TLP:AMBER+STRICT",
    }


# --- Step construction -------------------------------------------------------


def test_step_level_ignores_case():
    lower = mark(chain(DOMAIN_7), "amber+strict")
    upper = mark(chain(DOMAIN_7), "AMBER+STRICT")

    assert lower.objects[0].id == upper.objects[0].id == AMBER_STRICT_ID
    assert lower.serialize() == upper.serialize()


def test_step_white_is_clear():
    white = mark(chain(DOMAIN_7), "WHITE")
    clear = mark(chain(DOMAIN_7), "CLEAR")

    assert white.objects[0].id == CLEAR_ID
    assert white.serialize() == clear.serialize()


@pytest.mark.parametrize("value", ["PURPLE", "TLP:AMBER"])
def test_step_with_unknown_level_fails_naming_it(value):
    with pytest.raises(ValueError, match=f"'{value}'"):
        CrowdStrikeAddTlpMarking(value)


def test_step_takes_a_level():
    assert CrowdStrikeAddTlpMarking(TLPLevel.RED).marking.id == RED_ID


# --- Objects -----------------------------------------------------------------


@pytest.mark.parametrize("raw", SAMPLE_ROWS, ids=SAMPLE_IDS)
def test_marking_first_then_every_object_in_order(raw):
    bundle = chain(raw)

    result = mark(bundle)

    assert result.type == "bundle"
    assert result.id == bundle.id
    assert [obj.id for obj in result.objects] == [
        GREEN_ID,
        *(obj.id for obj in bundle.objects),
    ]
    assert result.objects[1].id == CROWDSTRIKE_IDENTITY_ID


def test_marking_is_not_repeated():
    once = mark(chain(DOMAIN_7))

    twice = mark(once)

    assert [obj.id for obj in twice.objects] == [obj.id for obj in once.objects]
    assert twice.serialize() == once.serialize()


def test_empty_bundle_gets_the_marking_only():
    result = mark(stix2.v21.Bundle())

    assert [obj.id for obj in result.objects] == [GREEN_ID]


@pytest.mark.parametrize("raw", SAMPLE_ROWS, ids=SAMPLE_IDS)
def test_every_object_but_the_identity_is_marked(raw):
    result = mark(chain(raw))

    assert all(obj.object_marking_refs == [GREEN_ID] for obj in result.objects[2:])


def test_attack_patterns_are_marked():
    result = mark(chain(SAMPLE_ROWS[0]))

    patterns = [obj for obj in result.objects if obj.type == "attack-pattern"]
    assert patterns
    assert all(obj.object_marking_refs == [GREEN_ID] for obj in patterns)


def test_identity_is_left_unmarked():
    bundle = chain(DOMAIN_7)

    result = mark(bundle)

    assert result.objects[1] is bundle.objects[0]
    assert "object_marking_refs" not in result.objects[1]


def test_other_marking_is_kept():
    malware = stix2.v21.Malware(
        name="A", is_family=True, object_marking_refs=[OTHER_MARKING]
    )

    result = mark(stix2.v21.Bundle(objects=[malware]), "RED")

    assert result.objects[1].object_marking_refs == [OTHER_MARKING, RED_ID]


def test_object_already_marked_with_the_level_is_unchanged():
    malware = stix2.v21.Malware(name="A", is_family=True, object_marking_refs=[RED_ID])

    result = mark(stix2.v21.Bundle(objects=[malware]), "RED")

    assert result.objects[1] is malware


def test_other_marking_definitions_are_left_unmarked():
    result = mark(stix2.v21.Bundle(objects=[stix2.v21.TLP_RED]))

    assert result.objects[1] is stix2.v21.TLP_RED


@pytest.mark.parametrize("raw", SAMPLE_ROWS, ids=SAMPLE_IDS)
def test_nothing_else_changes(raw):
    bundle = chain(raw)

    result = mark(bundle)

    for before, after in zip(bundle.objects, result.objects[1:], strict=True):
        assert type(after) is type(before)
        assert without(after, "object_marking_refs") == json.loads(before.serialize())


def test_custom_properties_are_kept():
    result = mark(chain(DOMAIN_7))

    parsed = stix2.parse(result.serialize(), allow_custom=True)

    indicator = parsed.objects[2]
    assert indicator.object_marking_refs == [GREEN_ID]
    assert indicator["x_crowdstrike_marker"] == DOMAIN_7["_marker"]
    assert indicator["x_crowdstrike_malware_families"] == DOMAIN_7["malware_families"]


def test_undeclared_custom_properties_are_kept():
    parsed = stix2.parse(chain(make_indicator(1)).serialize(), allow_custom=True)
    assert parsed.objects[1].has_custom

    result = mark(parsed)

    assert result.objects[2]["x_crowdstrike_marker"] == "1700000001x000001"
    assert result.objects[2].object_marking_refs == [GREEN_ID]


def test_input_bundle_is_left_unchanged():
    bundle = chain(SAMPLE_ROWS[0])
    serialized = bundle.serialize()

    mark(bundle)

    assert bundle.serialize() == serialized


# --- References --------------------------------------------------------------


@pytest.mark.parametrize("raw", SAMPLE_ROWS, ids=SAMPLE_IDS)
def test_no_missing_reference(raw):
    assert missing_references(mark(chain(raw)).objects) == []


# --- Determinism -------------------------------------------------------------


def test_same_input_same_output_whatever_the_time():
    bundle = chain(SAMPLE_ROWS[0])
    first = mark(bundle, "AMBER+STRICT")

    later = datetime(2099, 1, 1, tzinfo=UTC)
    with mock.patch("stix2.base.get_timestamp", return_value=later):
        second = mark(bundle, "AMBER+STRICT")

    assert first.serialize() == second.serialize()
