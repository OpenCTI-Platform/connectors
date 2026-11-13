"""Tests for the STIX 2.1 representation of a CrowdStrike indicator."""

import json

import pytest
import stix2
from crowdstrike_indicators.stix import CrowdStrikeStix2Indicator
from stix2.exceptions import ExtraPropertiesError

NATIVE = {
    "pattern": "[domain-name:value = 'malicious-1.example']",
    "pattern_type": "stix",
    "valid_from": "2026-11-01T00:00:00Z",
}

EVERY_X_PROPERTY = {
    "x_crowdstrike_id": "domain_malicious-1.example",
    "x_crowdstrike_indicator": "malicious-1.example",
    "x_crowdstrike_type": "domain",
    "x_crowdstrike_marker": "1793491203" + "0" * 32,
    "x_crowdstrike_last_updated": "2026-11-01T00:00:03Z",
    "x_crowdstrike_published_date": "2026-11-01T00:00:00Z",
    "x_crowdstrike_deleted": False,
    "x_crowdstrike_malicious_confidence": "high",
    "x_crowdstrike_actors": ["EXAMPLEBEAR"],
    "x_crowdstrike_malware_families": ["ExampleFamily1"],
    "x_crowdstrike_kill_chains": ["C2"],
    "x_crowdstrike_targets": ["Government"],
    "x_crowdstrike_vulnerabilities": ["CVE-2000-0001"],
    "x_crowdstrike_threat_types": ["Botnet"],
    "x_crowdstrike_domain_types": ["ActorControlled"],
    "x_crowdstrike_ip_address_types": ["Proxy"],
    "x_crowdstrike_labels": [
        {"name": "KillChain/C2", "created_on": "2026-11-01T00:00:00Z"}
    ],
    "x_crowdstrike_extra": {"scope": ["s1"]},
}


def _build(**properties) -> CrowdStrikeStix2Indicator:
    return CrowdStrikeStix2Indicator(
        id="indicator--00000000-0000-5000-8000-000000000001", **NATIVE, **properties
    )


def test_every_x_crowdstrike_property_is_accepted():
    indicator = _build(**EVERY_X_PROPERTY)

    assert isinstance(indicator, stix2.v21.Indicator)
    for name in EVERY_X_PROPERTY:
        assert name in indicator, name
    assert indicator.x_crowdstrike_actors == ["EXAMPLEBEAR"]
    assert indicator.x_crowdstrike_extra == {"scope": ["s1"]}


def test_undeclared_x_property_is_rejected():
    with pytest.raises(ExtraPropertiesError):
        _build(x_crowdstrike_unknown="value")


def test_serializes_as_a_standard_indicator():
    data = json.loads(_build(**EVERY_X_PROPERTY).serialize())

    assert data["type"] == "indicator"
    assert data["spec_version"] == "2.1"
    assert data["x_crowdstrike_kill_chains"] == ["C2"]


def test_parse_keeps_the_x_properties_only_with_allow_custom():
    serialized = _build(**EVERY_X_PROPERTY).serialize()

    parsed = stix2.parse(serialized, allow_custom=True)

    assert parsed["x_crowdstrike_labels"] == EVERY_X_PROPERTY["x_crowdstrike_labels"]
    with pytest.raises(ExtraPropertiesError):
        stix2.parse(serialized)


def test_goes_into_a_bundle():
    indicator = _build(**EVERY_X_PROPERTY)

    bundle = stix2.Bundle(objects=[indicator])

    assert bundle.objects[0].x_crowdstrike_type == "domain"
