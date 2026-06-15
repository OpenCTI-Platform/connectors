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
