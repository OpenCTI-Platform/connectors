from unittest.mock import MagicMock

import pytest
from connector.converter_to_stix import ConverterToStix


def _converter(tlp_level: str = "amber") -> ConverterToStix:
    return ConverterToStix(MagicMock(), tlp_level=tlp_level)


def test_author_is_identity():
    converter = _converter()
    assert converter.author["type"] == "identity"
    assert converter.author["name"] == "LogRhythm"


def test_amber_strict_marking():
    converter = _converter("amber+strict")
    assert converter.tlp_marking["definition_type"] == "statement"


def test_clear_marking_is_distinct_from_white():
    # TLP:CLEAR must be its own OpenCTI statement marking, not the STIX TLP:WHITE.
    clear = _converter("clear").tlp_marking
    white = _converter("white").tlp_marking
    assert clear["definition_type"] == "statement"
    assert clear["x_opencti_definition"] == "TLP:CLEAR"
    assert white.get("x_opencti_definition") != "TLP:CLEAR"


def test_to_iso_uses_deterministic_fallback():
    # Missing / invalid timestamps must yield a stable anchor so the generated
    # Incident / Case-Incident id does not change across runs (avoids duplicates).
    assert ConverterToStix._to_iso(None) == ConverterToStix._to_iso("")
    assert ConverterToStix._to_iso("not-a-date") == ConverterToStix._to_iso(None)
    assert ConverterToStix._to_iso(None).startswith("1970-01-01")


def test_case_incident_id_is_stable_without_timestamp():
    converter = _converter()
    first = converter.create_case_incident({"number": "42"})
    second = converter.create_case_incident({"number": "42"})
    assert first["id"] == second["id"]


@pytest.mark.parametrize(
    "value, expected",
    [
        (5, "critical"),
        (4, "high"),
        (3, "medium"),
        (2, "low"),
        (1, "low"),
        ("high", "high"),
        ("5", "critical"),
        (None, "low"),
    ],
)
def test_map_severity(value, expected):
    assert ConverterToStix._map_severity(value) == expected


@pytest.mark.parametrize(
    "value, expected",
    [(85, "critical"), (65, "high"), (45, "medium"), (10, "low"), (None, "low")],
)
def test_map_risk(value, expected):
    assert ConverterToStix._map_risk(value) == expected


def test_create_incident_from_alarm():
    converter = _converter()
    incident = converter.create_incident(
        {
            "alarmRuleName": "Brute force",
            "alarmId": "a1",
            "riskScore": 85,
            "alarmDate": "2024-05-01T00:00:00Z",
        }
    )
    assert incident["type"] == "incident"
    assert incident["name"] == "Brute force"
    assert incident["external_references"][0]["external_id"] == "a1"
    assert incident["incident_type"] == "alert"


def test_create_case_incident_with_object_refs():
    converter = _converter()
    incident = converter.create_incident({"alarmId": "a1", "riskScore": 85})
    case = converter.create_case_incident(
        {"name": "Case A", "number": "42"}, object_refs=[incident["id"]]
    )
    assert incident["id"] in case["object_refs"]


def test_create_case_incident():
    converter = _converter()
    case = converter.create_case_incident(
        {
            "name": "Case A",
            "number": "42",
            "priority": 5,
            "dateCreated": "2024-05-01T00:00:00Z",
            "summary": "Case details",
        }
    )
    assert case["type"] == "case-incident"
    assert case["name"] == "Case A"
    assert case["external_references"][0]["external_id"] == "42"
    assert case["priority"] == "P1"


def test_create_case_incident_minimal():
    converter = _converter()
    case = converter.create_case_incident({})
    assert case["name"] == "LogRhythm case"
