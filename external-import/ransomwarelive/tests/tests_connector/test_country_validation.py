"""Unit tests for the validation of the ransomware.live ``country`` field."""

from unittest.mock import MagicMock

import pytest
from ransomwarelive.converter_to_stix import ConverterToStix
from ransomwarelive.ransom_conn import RansomwareAPIConnector
from ransomwarelive.utils import normalize_country_code

# ---------------------------------------------------------------------------
# utils.normalize_country_code
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value, expected",
    [
        ("FR", "FR"),
        ("us", "US"),
        (" de ", "DE"),
        ("XK", "XK"),
    ],
)
def test_normalize_country_code_returns_valid_code(value, expected):
    assert normalize_country_code(value) == expected


@pytest.mark.parametrize(
    "value",
    [None, "", "  ", "NY", "EU", "QC", "VZ", "UK", "FRA", "New York", 42],
)
def test_normalize_country_code_returns_none_for_invalid_value(value):
    assert normalize_country_code(value) is None


# ---------------------------------------------------------------------------
# RansomwareAPIConnector.create_bundle_list
# ---------------------------------------------------------------------------


def _make_connector() -> RansomwareAPIConnector:
    """Build a connector with every optional entity disabled."""
    connector = RansomwareAPIConnector.__new__(RansomwareAPIConnector)
    connector.helper = MagicMock()
    # No country already in OpenCTI: location_fetcher falls back to create_country
    connector.helper.api.location.list.return_value = []
    connector.config = MagicMock()
    connector.config.ransomwarelive.create_threat_actor = False
    connector.config.ransomwarelive.create_intrusion_set = False
    connector.config.ransomwarelive.create_campaign = False
    connector.config.ransomwarelive.create_report = False
    connector.config.ransomwarelive.create_leak_post_refs = False
    connector.converter_to_stix = ConverterToStix("TLP:CLEAR")
    connector.author = connector.converter_to_stix.author
    connector.processed_groups = set()
    connector.country_cache = {}
    return connector


def _victim(country: str | None) -> dict:
    return {
        "victim": "Acme Corp",
        "group": "acme-ransomware",
        "country": country,
        "activity": "",
        "domain": "",
        "attackdate": "2026-06-01T00:00:00+00:00",
        "discovered": "2026-06-02T00:00:00+00:00",
    }


def _locations(bundle_objects: list) -> list:
    return [obj for obj in bundle_objects if obj and obj.get("type") == "location"]


def test_create_bundle_list_creates_location_for_valid_country():
    connector = _make_connector()

    bundle_objects = connector.create_bundle_list(_victim("fr"), group_data=[])

    locations = _locations(bundle_objects)
    assert len(locations) == 1
    assert locations[0]["name"] == "FR"
    connector.helper.connector_logger.warning.assert_not_called()


@pytest.mark.parametrize("country", ["NY", "EU", "QC", "VZ"])
def test_create_bundle_list_skips_location_for_invalid_country(country):
    connector = _make_connector()

    bundle_objects = connector.create_bundle_list(_victim(country), group_data=[])

    assert _locations(bundle_objects) == []
    # The victim itself is still ingested
    assert any(obj.get("name") == "Acme Corp" for obj in bundle_objects if obj)
    connector.helper.connector_logger.warning.assert_called_once_with(
        "Invalid country code, location skipped",
        {"country": country, "victim": "Acme Corp"},
    )


def test_create_bundle_list_skips_empty_country_silently():
    connector = _make_connector()

    bundle_objects = connector.create_bundle_list(_victim(""), group_data=[])

    assert _locations(bundle_objects) == []
    connector.helper.connector_logger.warning.assert_not_called()
