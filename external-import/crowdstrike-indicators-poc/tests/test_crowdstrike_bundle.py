"""Tests for turning a CrowdStrike indicator bundle into a STIX 2.1 bundle."""

import dataclasses
import json
from datetime import UTC, datetime
from typing import Any
from unittest import mock

import pytest
import stix2
from conftest import load_fixture, make_indicator
from crowdstrike_indicators.attack import (
    AttackPatternCatalog,
    CrowdStrikeAddAttackPatterns,
)
from crowdstrike_indicators.bundle import MakeStixBundle, missing_references
from crowdstrike_indicators.errors import IndicatorConversionError
from crowdstrike_indicators.malware import CrowdStrikeAddMalware
from crowdstrike_indicators.models import CrowdStrikeIndicator
from crowdstrike_indicators.stix import CrowdStrikeIndicatorBundle
from crowdstrike_indicators.transformer import CrowdStrikeIndicatorTransformer

SAMPLE_ROWS = load_fixture("indicators_sample.json")["resources"]
SAMPLE_IDS = [f"{row['type']}-{i}" for i, row in enumerate(SAMPLE_ROWS)]
DOMAIN_7 = next(row for row in SAMPLE_ROWS if row["id"] == "domain_malicious-7.example")
CATALOG = AttackPatternCatalog(load_fixture("attack_extract.json"))


def chain(raw: dict[str, Any]) -> CrowdStrikeIndicatorBundle:
    """Run the steps before ``MakeStixBundle``, attack patterns included."""
    indicator = CrowdStrikeIndicatorTransformer().convert(
        CrowdStrikeIndicator.model_validate(raw)
    )
    bundle = CrowdStrikeAddMalware().convert(indicator)
    return CrowdStrikeAddAttackPatterns(CATALOG).convert(bundle)


def make(bundle: CrowdStrikeIndicatorBundle) -> stix2.v21.Bundle:
    return MakeStixBundle().convert(bundle)


# --- Objects -----------------------------------------------------------------


@pytest.mark.parametrize("raw", SAMPLE_ROWS, ids=SAMPLE_IDS)
def test_bundle_holds_every_object_in_order(raw):
    item = chain(raw)

    result = make(item)

    expected = [
        item.indicator,
        *item.malware,
        *item.attack_patterns,
        *item.relationships,
    ]
    assert result.type == "bundle"
    assert [obj.id for obj in result.objects] == [obj.id for obj in expected]
    assert all(a is b for a, b in zip(result.objects, expected))


def test_indicator_with_malware_and_attack_patterns():
    item = chain(SAMPLE_ROWS[0])
    assert item.malware and item.attack_patterns

    types = [obj.type for obj in make(item).objects]

    malware, patterns = len(item.malware), len(item.attack_patterns)
    assert types == (
        ["indicator"]
        + ["malware"] * malware
        + ["attack-pattern"] * patterns
        + ["relationship"] * (malware + patterns)
    )


def test_indicator_alone():
    item = chain(make_indicator(1))
    assert not (item.malware or item.attack_patterns or item.relationships)

    result = make(item)

    assert [obj.id for obj in result.objects] == [item.indicator.id]


def test_custom_properties_are_kept():
    item = chain(DOMAIN_7)

    parsed = stix2.parse(make(item).serialize(), allow_custom=True)

    indicator = parsed.objects[0]
    assert indicator["x_crowdstrike_marker"] == DOMAIN_7["_marker"]
    assert indicator["x_crowdstrike_malware_families"] == DOMAIN_7["malware_families"]


# --- Id ----------------------------------------------------------------------


def test_bundle_id_is_pinned():
    item = chain(DOMAIN_7)

    result = make(item)

    assert item.indicator.id == "indicator--f975582d-ec64-5f6c-ac8c-1fdea0f69e0b"
    assert result.id == "bundle--fe24cab3-d021-56f9-af58-867c5a0cdb23"


# --- References --------------------------------------------------------------


def test_complete_bundle_has_no_missing_reference():
    item = chain(SAMPLE_ROWS[0])

    assert missing_references(make(item).objects) == []


def test_missing_target_is_rejected():
    item = chain(DOMAIN_7)
    removed = item.malware[0]
    broken = dataclasses.replace(item, malware=item.malware[1:])

    with pytest.raises(IndicatorConversionError) as caught:
        make(broken)

    assert caught.value.indicator_id == DOMAIN_7["id"]
    assert removed.id in str(caught.value)


def test_any_ref_property_is_checked():
    item = chain(make_indicator(1, malware_families=["A"]))
    malware = item.malware[0]
    orphan = stix2.v21.Malware(
        id=malware.id,
        name=malware.name,
        is_family=True,
        created=malware.created,
        modified=malware.modified,
        created_by_ref="identity--00000000-0000-5000-8000-000000000001",
    )

    with pytest.raises(IndicatorConversionError, match="identity--00000000"):
        make(dataclasses.replace(item, malware=[orphan]))


# --- Determinism -------------------------------------------------------------


def test_same_input_same_output_whatever_the_time():
    item = chain(SAMPLE_ROWS[0])
    first = make(item)

    later = datetime(2099, 1, 1, tzinfo=UTC)
    with mock.patch("stix2.base.get_timestamp", return_value=later):
        second = make(item)

    assert first.serialize() == second.serialize()
    assert json.loads(first.serialize())["id"] == first.id
