from unittest.mock import MagicMock

import pytest
from connector.converter_to_stix import ConverterToStix


def _converter(tlp_level: str = "amber") -> ConverterToStix:
    return ConverterToStix(MagicMock(), tlp_level=tlp_level)


def test_author_is_identity():
    converter = _converter()
    assert converter.author["type"] == "identity"
    assert converter.author["name"] == "ArcSight"


def test_amber_strict_marking():
    converter = _converter("amber+strict")
    assert converter.tlp_marking["definition_type"] == "statement"


def test_clear_marking_is_distinct_from_white():
    # TLP:CLEAR must be its own custom statement marking, not STIX TLP:WHITE.
    clear = _converter("clear").tlp_marking
    assert clear["definition_type"] == "statement"
    assert clear["x_opencti_definition"] == "TLP:CLEAR"
    white = _converter("white").tlp_marking
    assert white.get("name") == "TLP:WHITE"


@pytest.mark.parametrize(
    "value, expected_year",
    [
        (1700000000000, "2023"),
        (1700000000, "2023"),
        ("2024-05-01T00:00:00Z", "2024"),
    ],
)
def test_to_iso(value, expected_year):
    assert expected_year in ConverterToStix._to_iso(value)


def test_to_iso_none_returns_now():
    assert "T" in ConverterToStix._to_iso(None)


@pytest.mark.parametrize(
    "value, expected",
    [
        (10, "critical"),
        (8, "high"),
        (5, "medium"),
        (1, "low"),
        ("high", "high"),
        ("5", "medium"),
        (None, "low"),
    ],
)
def test_map_severity(value, expected):
    assert ConverterToStix._map_severity(value) == expected


def test_create_incident_from_event():
    converter = _converter()
    incident = converter.create_incident(
        {
            "name": "Suspicious login",
            "eventId": "e1",
            "priority": 9,
            "endTime": 1700000000000,
        }
    )
    assert incident["type"] == "incident"
    assert incident["name"] == "Suspicious login"
    assert incident["external_references"][0]["external_id"] == "e1"
    assert incident["incident_type"] == "alert"


def test_create_incident_base_event_ids():
    converter = _converter()
    incident = converter.create_incident({"baseEventIds": ["b9"], "priority": 3})
    assert incident["external_references"][0]["external_id"] == "b9"


def test_create_case_incident_with_object_refs():
    converter = _converter()
    incident = converter.create_incident({"eventId": "e1", "priority": 9})
    case = converter.create_case_incident(
        {"name": "Case A", "resourceid": "ABC"}, object_refs=[incident["id"]]
    )
    assert incident["id"] in case["object_refs"]


def test_create_case_incident():
    converter = _converter()
    case = converter.create_case_incident(
        {
            "name": "Investigation 42",
            "resourceid": "ABC123",
            "consequenceSeverity": 9,
            "createdTimestamp": 1700000000000,
            "message": "Case details",
        }
    )
    assert case["type"] == "case-incident"
    assert case["name"] == "Investigation 42"
    assert case["external_references"][0]["external_id"] == "ABC123"
    assert case["priority"] == "P1"


def test_create_case_incident_minimal():
    converter = _converter()
    case = converter.create_case_incident({})
    assert case["name"] == "ArcSight Case"


def test_incident_id_stable_without_timestamp():
    # No source timestamp: the id must not depend on "now", so re-importing the same
    # event keeps the same Incident id instead of creating duplicates each run.
    converter = _converter()
    event = {"name": "Suspicious login", "eventId": "e1", "priority": 9}
    assert (
        converter.create_incident(event)["id"] == converter.create_incident(event)["id"]
    )


def test_case_incident_id_stable_without_timestamp():
    converter = _converter()
    case = {"name": "Investigation 42", "resourceid": "ABC123"}
    assert (
        converter.create_case_incident(case)["id"]
        == converter.create_case_incident(case)["id"]
    )


def test_incident_id_stable_with_unparseable_timestamp():
    # An unparseable timestamp must not leak "now" into the id either: _parse_timestamp
    # returns None, so the id seed is None and stays stable across runs.
    converter = _converter()
    event = {"name": "x", "eventId": "e1", "endTime": "not-a-timestamp"}
    assert (
        converter.create_incident(event)["id"] == converter.create_incident(event)["id"]
    )


def test_create_incident_scalar_base_event_id():
    converter = _converter()
    incident = converter.create_incident({"baseEventIds": "b42", "priority": 3})
    assert incident["external_references"][0]["external_id"] == "b42"


def test_incidents_with_same_name_different_event_id_have_distinct_ids():
    # Distinct events that happen to share a name must not collapse into one
    # Incident: the event id is part of the id seed.
    converter = _converter()
    a = converter.create_incident({"name": "Same", "eventId": "e1"})
    b = converter.create_incident({"name": "Same", "eventId": "e2"})
    assert a["id"] != b["id"]


def test_incident_timestamps_use_stable_fallback_without_timestamp():
    # With no source timestamp, created/modified must be a fixed sentinel (not
    # "now"), so the same Incident is not re-sent with drifting timestamps.
    converter = _converter()
    incident = converter.create_incident({"name": "x", "eventId": "e1"})
    assert incident["created"] == incident["modified"]
    assert str(incident["created"]).startswith("1970-01-01")


def test_case_incidents_with_same_name_different_external_id_have_distinct_ids():
    converter = _converter()
    a = converter.create_case_incident({"name": "Same", "resourceid": "A"})
    b = converter.create_case_incident({"name": "Same", "resourceid": "B"})
    assert a["id"] != b["id"]


def test_case_incident_timestamps_use_stable_fallback_without_timestamp():
    converter = _converter()
    case = converter.create_case_incident({"name": "x", "resourceid": "A"})
    assert str(case["created"]).startswith("1970-01-01")
    assert str(case["modified"]).startswith("1970-01-01")


def test_case_incident_modified_falls_back_to_created_when_unparseable():
    # A non-empty but unparseable modified timestamp must fall back to the stable
    # created value (not "now"), so the deterministic id is not re-sent with a
    # drifting modified each run.
    converter = _converter()
    case = converter.create_case_incident(
        {
            "name": "x",
            "resourceid": "A",
            "createdTimestamp": 1700000000000,
            "modifiedTimestamp": "not-a-timestamp",
        }
    )
    assert case["modified"] == case["created"]
