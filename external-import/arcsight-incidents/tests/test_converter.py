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
