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
