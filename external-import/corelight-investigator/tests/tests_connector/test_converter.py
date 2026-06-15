from unittest.mock import MagicMock

import pytest
from connector.converter_to_stix import ConverterToStix


def _converter(tlp_level: str = "amber") -> ConverterToStix:
    return ConverterToStix(MagicMock(), tlp_level=tlp_level)


def test_author_is_identity():
    converter = _converter()
    assert converter.author["type"] == "identity"
    assert converter.author["name"] == "Corelight Investigator"


def test_amber_strict_marking():
    converter = _converter("amber+strict")
    assert converter.tlp_marking["definition_type"] == "statement"


@pytest.mark.parametrize(
    "value, expected",
    [
        (10, "critical"),
        (9, "critical"),
        (7, "high"),
        (4, "medium"),
        (1, "low"),
        (None, "low"),
    ],
)
def test_map_severity(value, expected):
    assert ConverterToStix._map_severity(value) == expected


def test_create_incident():
    converter = _converter()
    incident = converter.create_incident(
        {
            "alert_id": "a-1",
            "name": "Beaconing detected",
            "EventType": "Detection",
            "severity": 9,
            "timestamp": "2024-05-01T00:00:00Z",
            "description": "C2 beaconing",
        }
    )
    assert incident["type"] == "incident"
    assert incident["name"] == "Beaconing detected"
    assert incident["external_references"][0]["external_id"] == "a-1"
    assert incident["incident_type"] == "detection"
    assert incident["severity"] == "critical"


def test_create_incident_default_name():
    converter = _converter()
    incident = converter.create_incident({"alert_id": "x", "EventType": "Alert"})
    assert incident["name"] == "Corelight Alert x"


def test_create_observables():
    converter = _converter()
    objects = converter.create_observables(
        {"src_ip": "1.2.3.4", "dest_ip": "2001:db8::1"},
        "incident--11111111-1111-4111-8111-111111111111",
    )
    types = {o["type"] for o in objects}
    assert "ipv4-addr" in types
    assert "ipv6-addr" in types
    assert "relationship" in types


def test_create_observables_skips_invalid():
    converter = _converter()
    objects = converter.create_observables(
        {"src_ip": "not-an-ip", "dest_ip": ""},
        "incident--11111111-1111-4111-8111-111111111111",
    )
    assert objects == []
