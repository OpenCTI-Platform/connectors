"""Unit tests for the lookup of the victim country in OpenCTI (#4556)."""

from unittest.mock import MagicMock

from pycti import Location
from ransomwarelive.converter_to_stix import ConverterToStix
from ransomwarelive.ransom_conn import RansomwareAPIConnector

GERMANY = {
    "id": "germany-internal-id",
    "standard_id": "location--11111111-1111-4111-8111-111111111111",
    "name": "Germany",
    "x_opencti_aliases": ["DEU", "DE"],
    "created_at": "2024-01-01T00:00:00.000Z",
}
ROGUE_DE = {
    "id": "rogue-de-internal-id",
    "standard_id": Location.generate_id("DE", "Country"),
    "name": "DE",
    "x_opencti_aliases": None,
    "created_at": "2025-06-01T00:00:00.000Z",
}


def _make_connector(existing_countries=None) -> RansomwareAPIConnector:
    connector = RansomwareAPIConnector.__new__(RansomwareAPIConnector)
    connector.helper = MagicMock()
    connector.helper.api.location.list.return_value = existing_countries or []
    connector.helper.api.stix2.get_stix_bundle_or_object_from_entity_id.side_effect = (
        lambda entity_type, entity_id, only_entity: {
            "type": "location",
            "id": f"stix-of-{entity_id}",
        }
    )
    connector.converter_to_stix = ConverterToStix("TLP:CLEAR")
    connector.country_cache = {}
    return connector


def _exported_entity_ids(connector) -> list:
    export = connector.helper.api.stix2.get_stix_bundle_or_object_from_entity_id
    return [call.kwargs["entity_id"] for call in export.call_args_list]


def test_location_fetcher_searches_countries_by_name_or_alias():
    connector = _make_connector()

    connector.location_fetcher("DE")

    kwargs = connector.helper.api.location.list.call_args.kwargs
    assert kwargs["types"] == ["Country"]
    assert kwargs["filters"] == {
        "mode": "or",
        "filters": [
            {"key": "name", "values": ["DE"], "operator": "eq"},
            {"key": "x_opencti_aliases", "values": ["DE"], "operator": "eq"},
        ],
        "filterGroups": [],
    }
    connector.helper.api.stix_domain_object.read.assert_not_called()


def test_location_fetcher_uses_the_country_holding_the_code_as_alias():
    connector = _make_connector([GERMANY])

    location = connector.location_fetcher("DE")

    assert location == {"type": "location", "id": "stix-of-germany-internal-id"}
    connector.helper.connector_logger.warning.assert_not_called()


def test_location_fetcher_prefers_the_alias_match_over_a_rogue_country():
    # A rogue "DE" country created by an older run, newer than the seed one
    connector = _make_connector([ROGUE_DE, GERMANY])

    location = connector.location_fetcher("DE")

    assert location["id"] == "stix-of-germany-internal-id"
    connector.helper.connector_logger.warning.assert_called_once_with(
        "Several countries match the country code, one is used",
        {"country": "DE", "count": 2, "selected": "Germany"},
    )


def test_location_fetcher_prefers_the_oldest_country_among_alias_matches():
    newer_germany = {
        **GERMANY,
        "id": "newer-germany-internal-id",
        "created_at": "2026-01-01T00:00:00.000Z",
    }
    connector = _make_connector([newer_germany, GERMANY])

    location = connector.location_fetcher("DE")

    assert location["id"] == "stix-of-germany-internal-id"


def test_location_fetcher_matches_aliases_case_insensitively():
    connector = _make_connector(
        [ROGUE_DE, {**GERMANY, "x_opencti_aliases": ["deu", "de"]}]
    )

    location = connector.location_fetcher("DE")

    assert location["id"] == "stix-of-germany-internal-id"


def test_location_fetcher_reuses_a_country_named_with_the_code():
    connector = _make_connector([ROGUE_DE])

    location = connector.location_fetcher("DE")

    assert location["id"] == "stix-of-rogue-de-internal-id"


def test_location_fetcher_creates_the_country_when_none_exists():
    connector = _make_connector([])

    location = connector.location_fetcher("DE")

    assert location["id"] == Location.generate_id("DE", "Country")
    assert location["name"] == "DE"
    assert _exported_entity_ids(connector) == []


def test_location_fetcher_caches_the_result_for_the_run():
    connector = _make_connector([GERMANY])

    first = connector.location_fetcher("DE")
    second = connector.location_fetcher("DE")

    assert first == second
    connector.helper.api.location.list.assert_called_once()
    assert _exported_entity_ids(connector) == ["germany-internal-id"]


def test_location_fetcher_returns_none_and_does_not_cache_on_error():
    connector = _make_connector()
    connector.helper.api.location.list.side_effect = [Exception("boom"), [GERMANY]]

    assert connector.location_fetcher("DE") is None
    connector.helper.connector_logger.error.assert_called_once()

    assert connector.location_fetcher("DE")["id"] == "stix-of-germany-internal-id"


def test_location_fetcher_does_not_cache_an_empty_export():
    connector = _make_connector([GERMANY])
    export = connector.helper.api.stix2.get_stix_bundle_or_object_from_entity_id
    export.side_effect = [None, {"type": "location", "id": "stix-of-germany"}]

    assert connector.location_fetcher("DE") is None
    assert connector.country_cache == {}

    assert connector.location_fetcher("DE")["id"] == "stix-of-germany"
    assert connector.helper.api.location.list.call_count == 2


def test_collect_intelligence_resets_the_country_cache():
    connector = _make_connector()
    connector.country_cache = {"DE": {"id": "stale"}}
    connector.api_client = MagicMock()
    connector.api_client.get_groups.return_value = None

    connector.collect_intelligence()

    assert connector.country_cache == {}


def test_collect_historic_intelligence_resets_the_country_cache():
    connector = _make_connector()
    connector.country_cache = {"DE": {"id": "stale"}}
    connector.api_client = MagicMock()
    connector.api_client.get_groups.return_value = None

    connector.collect_historic_intelligence()

    assert connector.country_cache == {}
