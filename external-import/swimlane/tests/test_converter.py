from unittest.mock import MagicMock

import pytest
from connector.converter_to_stix import ConverterToStix


def _converter(tlp_level: str = "amber") -> ConverterToStix:
    return ConverterToStix(MagicMock(), tlp_level=tlp_level)


def test_author_is_identity():
    converter = _converter()
    assert converter.author["type"] == "identity"
    assert converter.author["name"] == "Swimlane"


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
    # Case-Incident id does not change across runs (avoids duplicates).
    assert ConverterToStix._to_iso(None) == ConverterToStix._to_iso("")
    assert ConverterToStix._to_iso("not-a-date") == ConverterToStix._to_iso(None)
    assert ConverterToStix._to_iso(None).startswith("1970-01-01")


def test_to_iso_handles_out_of_range_epoch():
    # An out-of-range epoch must not raise OverflowError/OSError; it falls back to
    # the deterministic anchor instead of crashing the run.
    assert ConverterToStix._to_iso(10**30).startswith("1970-01-01")
    assert ConverterToStix._to_iso("9" * 400).startswith("1970-01-01")


def test_case_incident_id_is_stable_without_timestamp():
    converter = _converter()
    first = converter.create_case_incident({"trackingId": "INC-1"})
    second = converter.create_case_incident({"trackingId": "INC-1"})
    assert first["id"] == second["id"]


@pytest.mark.parametrize(
    "value, expected_year",
    [
        (1700000000000, "2023"),
        ("2024-05-01T00:00:00Z", "2024"),
    ],
)
def test_to_iso(value, expected_year):
    assert expected_year in ConverterToStix._to_iso(value)


def test_create_case_incident():
    converter = _converter()
    case = converter.create_case_incident(
        {
            "trackingId": "INC-42",
            "id": "rec-123",
            "createdDate": "2024-05-01T00:00:00Z",
        }
    )
    assert case["type"] == "case-incident"
    assert case["name"] == "Swimlane incident INC-42"
    assert case["external_references"][0]["external_id"] == "rec-123"


def test_create_case_incident_minimal():
    converter = _converter()
    case = converter.create_case_incident({})
    assert case["name"] == "Swimlane incident"
