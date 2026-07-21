from unittest.mock import MagicMock

import pytest
from connector.converter_to_stix import ConverterToStix


def _converter(tlp_level: str = "amber") -> ConverterToStix:
    return ConverterToStix(MagicMock(), tlp_level=tlp_level)


def test_author_is_identity():
    converter = _converter()
    assert converter.author["type"] == "identity"
    assert converter.author["name"] == "FortiSIEM"


def test_amber_strict_marking():
    converter = _converter("amber+strict")
    assert converter.tlp_marking["definition_type"] == "statement"


def test_clear_marking_is_distinct_tlp_clear():
    # TLP:CLEAR must be its own custom statement marking, not an alias of TLP:WHITE.
    converter = _converter("clear")
    assert converter.tlp_marking["definition_type"] == "statement"
    assert converter.tlp_marking["x_opencti_definition"] == "TLP:CLEAR"


@pytest.mark.parametrize(
    "value, expected_year",
    [
        (1700000000000, "2023"),  # milliseconds
        (1700000000, "2023"),  # seconds
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


def test_create_incident():
    converter = _converter()
    incident = converter.create_incident(
        {
            "incidentTitle": "Suspicious login",
            "incidentId": 123,
            "incidentSeverity": 9,
            "incidentFirstSeen": 1700000000000,
            "incidentDetail": "Details",
        }
    )
    assert incident["type"] == "incident"
    assert incident["name"] == "Suspicious login"
    assert incident["external_references"][0]["external_id"] == "123"


def test_create_incident_minimal():
    converter = _converter()
    incident = converter.create_incident({})
    assert incident["name"] == "FortiSIEM Incident"


def test_create_incident_id_stable_without_timestamp():
    # With no source timestamp, the id must not depend on "now", so re-importing the
    # same incident keeps the same id instead of creating duplicates each run.
    converter = _converter()
    incident = {"incidentTitle": "Suspicious login", "incidentId": 123}
    assert (
        converter.create_incident(incident)["id"]
        == converter.create_incident(incident)["id"]
    )


@pytest.mark.parametrize(
    "value, stix_type",
    [
        ("198.51.100.1", "ipv4-addr"),
        ("2001:db8::1", "ipv6-addr"),
        ("evil.example.com", "domain-name"),
    ],
)
def test_create_observable(value, stix_type):
    converter = _converter()
    observable = converter.create_observable(value)
    assert observable["type"] == stix_type


@pytest.mark.parametrize("value", ["", "not an observable"])
def test_create_observable_none(value):
    converter = _converter()
    assert converter.create_observable(value) is None


@pytest.mark.parametrize("value", ["198.51.100.1", "2001:db8::1", "evil.example.com"])
def test_observable_carries_x_opencti_created_by_ref(value):
    # SCOs must attribute the author via x_opencti_created_by_ref (not created_by_ref),
    # otherwise OpenCTI ignores the attribution.
    converter = _converter()
    observable = converter.create_observable(value)
    assert observable["x_opencti_created_by_ref"] == converter.author["id"]


def test_create_relationship():
    converter = _converter()
    incident = converter.create_incident({"incidentTitle": "x"})
    observable = converter.create_observable("198.51.100.1")
    rel = converter.create_relationship(incident["id"], "related-to", observable["id"])
    assert rel["relationship_type"] == "related-to"
    assert rel["source_ref"] == incident["id"]
