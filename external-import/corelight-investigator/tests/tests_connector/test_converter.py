import json
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
    assert converter.tlp_marking["x_opencti_definition"] == "TLP:AMBER+STRICT"


def test_clear_marking_is_statement_not_white():
    # TLP:CLEAR must be a distinct statement marking, not an alias of TLP:WHITE,
    # so OpenCTI shows the correct label.
    clear = _converter("clear").tlp_marking
    assert clear["definition_type"] == "statement"
    assert clear["x_opencti_definition"] == "TLP:CLEAR"

    white = _converter("white").tlp_marking
    assert white["definition_type"] == "tlp"


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


def test_incident_id_is_stable_without_timestamp():
    # No source timestamp: the id must not depend on "now", so re-importing the same
    # alert keeps the same Incident id instead of creating duplicates each run.
    converter = _converter()
    alert = {"alert_id": "x", "EventType": "Alert"}
    assert (
        converter.create_incident(alert)["id"] == converter.create_incident(alert)["id"]
    )


def test_incidents_with_same_name_different_id_have_distinct_ids():
    # Distinct alerts that happen to share a name must not collapse into one
    # Incident: the alert id is part of the id seed.
    converter = _converter()
    a = converter.create_incident({"alert_id": "a-1", "name": "Same"})
    b = converter.create_incident({"alert_id": "a-2", "name": "Same"})
    assert a["id"] != b["id"]


def test_incident_timestamps_use_stable_fallback_without_timestamp():
    # With no source timestamp, created/modified must be a fixed sentinel (not
    # "now"), so the same Incident is not re-sent with drifting timestamps.
    converter = _converter()
    incident = converter.create_incident({"alert_id": "x", "EventType": "Alert"})
    assert incident["created"] == incident["modified"]
    assert str(incident["created"]).startswith("1970-01-01")


def test_incident_uses_source_timestamp():
    # The STIX created/modified must reflect the source timestamp, not "now".
    converter = _converter()
    incident = converter.create_incident(
        {"alert_id": "a-1", "name": "n", "timestamp": "2024-05-01T00:00:00Z"}
    )
    serialized = json.loads(incident.serialize())
    assert serialized["created"].startswith("2024-05-01T00:00:00")
    assert serialized["modified"] == serialized["created"]


@pytest.mark.parametrize("value", [None, "", "not-a-date"])
def test_parse_timestamp_returns_none_for_invalid(value):
    assert ConverterToStix._parse_timestamp(value) is None


def test_parse_timestamp_handles_epoch_seconds_and_millis():
    assert ConverterToStix._parse_timestamp(0).year == 1970
    assert ConverterToStix._parse_timestamp(
        1_700_000_000_000
    ) == ConverterToStix._parse_timestamp(1_700_000_000)


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
