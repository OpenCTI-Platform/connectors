"""Tests for marking a STIX bundle with one TLP level."""

import json

import pytest
from crowdstrike_indicators.transform.add_tlp_marking import (
    MARKING_DEFINITIONS,
    TLPLevel,
)

CLEAR_ID = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
GREEN_ID = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
AMBER_ID = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
AMBER_STRICT_ID = "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"
RED_ID = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"
TLP_DATE = "2017-01-20T00:00:00.000Z"


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
