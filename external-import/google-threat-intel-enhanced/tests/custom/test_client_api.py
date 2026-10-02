"""Module to test the ClientAPI class (connector/src/custom/client_api.py)."""

import logging
from types import SimpleNamespace
from typing import Any, List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest
from connector.src.custom.client_api import ClientAPI

LOG_PREFIX = "[Fetchers]"

# =====================
# Fixtures
# =====================


@pytest.fixture
def logger() -> logging.Logger:
    """Fixture for a real logger so log-formatting code paths execute."""
    return logging.getLogger("test_client_api")


@pytest.fixture
def gti_config() -> Any:
    """Fixture for a minimal GTI-like configuration object."""
    return SimpleNamespace(
        api_key="fake-key",
        api_url="https://fake-gti.api",
        x_tool="OpenCTI.GTIConnector.v1.0",
        import_start_date="P1D",
        report_types=["All"],
        origins=["All"],
        campaign_origins=["google threat intelligence"],
        threat_actor_origins=["google threat intelligence"],
        malware_family_origins=["google threat intelligence"],
        vulnerability_origins=["google threat intelligence"],
    )


@pytest.fixture
def client_api(gti_config: Any, logger: logging.Logger) -> ClientAPI:
    """Fixture for a ClientAPI instance backed by the fake config."""
    return ClientAPI(gti_config, logger)


def _make_fetcher(fetch_single_results: Optional[List[Any]] = None) -> Any:
    """Build a fake fetcher exposing fetch_single/fetch_multiple as AsyncMocks."""
    fetcher = MagicMock()
    fetcher.fetch_single = AsyncMock(side_effect=fetch_single_results)
    fetcher.fetch_multiple = AsyncMock(return_value=[])
    return fetcher


async def _collect(async_gen: Any) -> List[Any]:
    """Collect all items yielded by an async generator."""
    return [item async for item in async_gen]


# =====================
# Test Cases: construction
# =====================


# Scenario: Construct the client with a fully configured API URL
def test_init_creates_api_client_and_factory(client_api: ClientAPI) -> None:
    """Test that construction wires up an api_client and fetcher_factory."""
    assert client_api.api_client is not None  # noqa: S101
    assert client_api.fetcher_factory is not None  # noqa: S101


# Scenario: Construct the client without an API URL configured
def test_init_without_api_url_logs_warning(logger: logging.Logger) -> None:
    """Test that construction still succeeds when api_url is missing."""
    config = SimpleNamespace(api_key="fake-key")
    client = ClientAPI(config, logger)
    assert client.api_client is not None  # noqa: S101


# =====================
# Test Cases: _build_filter_configurations (reports)
# =====================


# Scenario: Build report filters with default report types and origins
def test_build_filter_configurations_default(client_api: ClientAPI) -> None:
    """Test that the default report filter configuration covers all types and origins."""
    configs = client_api._build_filter_configurations(None)
    assert len(configs) == 1  # noqa: S101
    assert configs[0]["description"] == "all reports"  # noqa: S101
    assert configs[0]["cursor"] is None  # noqa: S101


# Scenario: Build report filters resuming from an initial state
def test_build_filter_configurations_resumes_from_state(client_api: ClientAPI) -> None:
    """Test that a next_cursor_start_date and cursor in initial_state are honored."""
    initial_state = {
        "next_cursor_start_date": "2024-07-11T20:05:01+00:00",
        "cursor": "abc123",
    }
    configs = client_api._build_filter_configurations(initial_state)
    assert configs[0]["cursor"] == "abc123"  # noqa: S101
    assert "2024-07-11T20:05:02" in configs[0]["params"]["filter"]  # noqa: S101


# Scenario: Build report filters across specific report types and origins
def test_build_filter_configurations_types_and_origins(client_api: ClientAPI) -> None:
    """Test that filter configs are built for each report_type x origin combination."""
    client_api.config.report_types = ["Actor Profile", "Patch Report"]
    client_api.config.origins = ["partner", "crowdsourced"]
    configs = client_api._build_filter_configurations(None)
    descriptions = {c["description"] for c in configs}
    assert descriptions == {  # noqa: S101
        "type=Actor Profile, origin=partner",
        "type=Actor Profile, origin=crowdsourced",
        "type=Patch Report, origin=partner",
        "type=Patch Report, origin=crowdsourced",
    }


# Scenario: Build report filters for all types with specific origins
def test_build_filter_configurations_all_types_specific_origins(
    client_api: ClientAPI,
) -> None:
    """Test the 'all types, origin=X' description branch."""
    client_api.config.report_types = ["All"]
    client_api.config.origins = ["partner", "crowdsourced"]
    configs = client_api._build_filter_configurations(None)
    descriptions = {c["description"] for c in configs}
    assert descriptions == {  # noqa: S101
        "all types, origin=partner",
        "all types, origin=crowdsourced",
    }


# Scenario: Build report filters for specific types with all origins
def test_build_filter_configurations_specific_types_all_origins(
    client_api: ClientAPI,
) -> None:
    """Test the 'type=X, all origins' description branch."""
    client_api.config.report_types = ["Actor Profile", "Patch Report"]
    client_api.config.origins = ["All"]
    configs = client_api._build_filter_configurations(None)
    descriptions = {c["description"] for c in configs}
    assert descriptions == {  # noqa: S101
        "type=Actor Profile, all origins",
        "type=Patch Report, all origins",
    }


# Scenario: A single "All" among several report types/origins collapses the whole list
def test_build_filter_configurations_all_collapses_list(client_api: ClientAPI) -> None:
    """Test that including 'All' anywhere in report_types/origins collapses it to just 'All'."""
    client_api.config.report_types = ["Actor Profile", "All"]
    client_api.config.origins = ["partner", "All"]
    configs = client_api._build_filter_configurations(None)
    assert [c["description"] for c in configs] == ["all reports"]  # noqa: S101


# Scenario: Build report filters falls back gracefully on unexpected errors
def test_build_filter_configurations_error_fallback(client_api: ClientAPI) -> None:
    """Test that an invalid import_start_date falls back to a safe default config."""
    client_api.config.import_start_date = "not-a-duration"
    configs = client_api._build_filter_configurations({"cursor": "xyz"})
    assert len(configs) == 1  # noqa: S101
    assert configs[0]["description"] == "fallback all reports"  # noqa: S101
    assert configs[0]["cursor"] == "xyz"  # noqa: S101


# =====================
# Test Cases: entity-specific filter builders
# =====================


@pytest.mark.parametrize(
    ("builder_name", "config_field", "state_key", "cursor_key", "collection_type"),
    [
        (
            "_build_campaign_filter_configurations",
            "campaign_origins",
            "next_cursor_start_date_campaigns",
            "campaign_cursor",
            "campaign",
        ),
        (
            "_build_threat_actor_filter_configurations",
            "threat_actor_origins",
            "next_cursor_start_date_threat_actors",
            "threat_actor_cursor",
            "threat-actor",
        ),
        (
            "_build_malware_filter_configurations",
            "malware_family_origins",
            "next_cursor_start_date_malware",
            "malware_cursor",
            "malware-family",
        ),
        (
            "_build_vulnerability_filter_configurations",
            "vulnerability_origins",
            "next_cursor_start_date_vulnerabilities",
            "vulnerability_cursor",
            "vulnerability",
        ),
    ],
)
def test_entity_filter_builders_default(
    client_api: ClientAPI,
    builder_name: str,
    config_field: str,
    state_key: str,
    cursor_key: str,
    collection_type: str,
) -> None:
    """Test that each entity-specific filter builder defaults to a single 'All origins' config."""
    builder = getattr(client_api, builder_name)
    configs = builder(None)
    assert len(configs) == 1  # noqa: S101
    assert (
        f"collection_type:{collection_type}" in configs[0]["params"]["filter"]
    )  # noqa: S101
    assert configs[0]["cursor"] is None  # noqa: S101


@pytest.mark.parametrize(
    ("builder_name", "config_field", "state_key", "cursor_key"),
    [
        (
            "_build_campaign_filter_configurations",
            "campaign_origins",
            "next_cursor_start_date_campaigns",
            "campaign_cursor",
        ),
        (
            "_build_threat_actor_filter_configurations",
            "threat_actor_origins",
            "next_cursor_start_date_threat_actors",
            "threat_actor_cursor",
        ),
        (
            "_build_malware_filter_configurations",
            "malware_family_origins",
            "next_cursor_start_date_malware",
            "malware_cursor",
        ),
        (
            "_build_vulnerability_filter_configurations",
            "vulnerability_origins",
            "next_cursor_start_date_vulnerabilities",
            "vulnerability_cursor",
        ),
    ],
)
def test_entity_filter_builders_resume_and_multi_origin(
    client_api: ClientAPI,
    builder_name: str,
    config_field: str,
    state_key: str,
    cursor_key: str,
) -> None:
    """Test that entity-specific filter builders resume from state and split comma-separated origins."""
    setattr(client_api.config, config_field, "partner, crowdsourced")
    initial_state = {state_key: "2024-07-11T20:05:01+00:00", cursor_key: "cur-1"}
    builder = getattr(client_api, builder_name)
    configs = builder(initial_state)
    assert len(configs) == 2  # noqa: S101
    assert {c["cursor"] for c in configs} == {"cur-1"}  # noqa: S101
    descriptions = {c["description"] for c in configs}
    assert any("partner" in d for d in descriptions)  # noqa: S101
    assert any("crowdsourced" in d for d in descriptions)  # noqa: S101


@pytest.mark.parametrize(
    ("builder_name", "config_field", "all_description"),
    [
        ("_build_campaign_filter_configurations", "campaign_origins", "all campaigns"),
        (
            "_build_threat_actor_filter_configurations",
            "threat_actor_origins",
            "all threat actors",
        ),
        (
            "_build_malware_filter_configurations",
            "malware_family_origins",
            "all malware families",
        ),
        (
            "_build_vulnerability_filter_configurations",
            "vulnerability_origins",
            "all vulnerabilities",
        ),
    ],
)
def test_entity_filter_builders_all_origins_collapse(
    client_api: ClientAPI, builder_name: str, config_field: str, all_description: str
) -> None:
    """Test that a list containing 'All' collapses to a single 'all X' description."""
    setattr(client_api.config, config_field, ["partner", "All"])
    builder = getattr(client_api, builder_name)
    configs = builder(None)
    assert [c["description"] for c in configs] == [all_description]  # noqa: S101


@pytest.mark.parametrize(
    ("builder_name", "config_field"),
    [
        ("_build_campaign_filter_configurations", "campaign_origins"),
        ("_build_threat_actor_filter_configurations", "threat_actor_origins"),
        ("_build_malware_filter_configurations", "malware_family_origins"),
        ("_build_vulnerability_filter_configurations", "vulnerability_origins"),
    ],
)
def test_entity_filter_builders_error_fallback(
    client_api: ClientAPI, builder_name: str, config_field: str
) -> None:
    """Test that entity-specific filter builders fall back on an invalid import_start_date."""
    client_api.config.import_start_date = "not-a-duration"
    builder = getattr(client_api, builder_name)
    configs = builder(None)
    assert len(configs) == 1  # noqa: S101
    assert "fallback" in configs[0]["description"]  # noqa: S101


# =====================
# Test Cases: response/meta extraction helpers
# =====================


# Scenario: Extract data from a response object exposing a .data attribute
def test_extract_response_data_from_object(client_api: ClientAPI) -> None:
    """Test extraction of data/meta from an object exposing .data and .meta."""
    response = SimpleNamespace(data=["a", "b"], meta=SimpleNamespace(cursor="c1"))
    data, meta = client_api._extract_response_data(response)
    assert data == ["a", "b"]  # noqa: S101
    assert meta.cursor == "c1"  # noqa: S101


# Scenario: Extract data from a plain dict response
def test_extract_response_data_from_dict(client_api: ClientAPI) -> None:
    """Test extraction of data/meta from a dict response."""
    response = {"data": ["a"], "meta": {"cursor": "c2"}}
    data, meta = client_api._extract_response_data(response)
    assert data == ["a"]  # noqa: S101
    assert meta == {"cursor": "c2"}  # noqa: S101


# Scenario: Extract data from a response with no recognizable shape
def test_extract_response_data_fallback(client_api: ClientAPI) -> None:
    """Test extraction fallback when the response has no data field."""
    data, meta = client_api._extract_response_data(["raw"])
    assert data == ["raw"]  # noqa: S101
    assert meta is None  # noqa: S101


# Scenario: Extract cursor/count from an empty meta
def test_extract_meta_info_empty(client_api: ClientAPI) -> None:
    """Test that extracting meta info from None returns (None, None)."""
    cursor, count = client_api._extract_meta_info(None)
    assert cursor is None  # noqa: S101
    assert count is None  # noqa: S101


# Scenario: Extract cursor/count from a meta object
def test_extract_meta_info_from_object(client_api: ClientAPI) -> None:
    """Test extraction of cursor/count from an object exposing attributes."""
    meta = SimpleNamespace(cursor="c1", count=42)
    cursor, count = client_api._extract_meta_info(meta)
    assert cursor == "c1"  # noqa: S101
    assert count == 42  # noqa: S101


# Scenario: Extract cursor/count from a meta dict
def test_extract_meta_info_from_dict(client_api: ClientAPI) -> None:
    """Test extraction of cursor/count from a dict."""
    cursor, count = client_api._extract_meta_info({"cursor": "c3", "count": 7})
    assert cursor == "c3"  # noqa: S101
    assert count == 7  # noqa: S101


# Scenario: Calculate pagination info with a known count
def test_calculate_pagination_info(client_api: ClientAPI) -> None:
    """Test total-pages calculation given a count and limit."""
    result = client_api._calculate_pagination_info(95, {"limit": 40})
    assert result == 3  # noqa: S101


# Scenario: Calculate pagination info with no count available
def test_calculate_pagination_info_none(client_api: ClientAPI) -> None:
    """Test that pagination info is None when count is unavailable."""
    assert (
        client_api._calculate_pagination_info(None, {"limit": 40}) is None
    )  # noqa: S101


# Scenario: Build a log message including page and cursor info
def test_build_log_message_with_pages_and_cursor(client_api: ClientAPI) -> None:
    """Test that the log message includes page progress and a truncated cursor."""
    message = client_api._build_log_message(10, "reports", 2, 5, 200, "abcdef123")
    assert "page 2/5" in message  # noqa: S101
    assert "total of 200 items" in message  # noqa: S101
    assert "abcdef" in message  # noqa: S101
    assert client_api.real_total_reports == 200  # noqa: S101


# Scenario: Build a log message with only a total item count
def test_build_log_message_total_items_only(client_api: ClientAPI) -> None:
    """Test that the log message shows the total when there is only a single page."""
    message = client_api._build_log_message(3, "malware_families", 1, None, 3, None)
    assert "total of 3 items" in message  # noqa: S101


# =====================
# Test Cases: _paginate_with_cursor
# =====================


# Scenario: Paginate across multiple pages using the returned cursor
@pytest.mark.asyncio
async def test_paginate_with_cursor_multiple_pages(client_api: ClientAPI) -> None:
    """Test that pagination follows the cursor across pages until it disappears."""
    fetcher = _make_fetcher(
        [
            SimpleNamespace(
                data=["a", "b"], meta=SimpleNamespace(cursor="next", count=3)
            ),
            SimpleNamespace(data=["c"], meta=SimpleNamespace(cursor=None, count=3)),
        ]
    )
    pages = await _collect(
        client_api._paginate_with_cursor(fetcher, {"limit": 2}, "items")
    )
    assert pages == [["a", "b"], ["c"]]  # noqa: S101
    assert fetcher.fetch_single.call_count == 2  # noqa: S101


# Scenario: Paginate stops when the fetcher returns no response
@pytest.mark.asyncio
async def test_paginate_with_cursor_none_response(client_api: ClientAPI) -> None:
    """Test that pagination stops cleanly when the fetcher returns None."""
    fetcher = _make_fetcher([None])
    pages = await _collect(
        client_api._paginate_with_cursor(fetcher, {"limit": 2}, "items")
    )
    assert pages == []  # noqa: S101


# Scenario: Paginate stops when the response has no data
@pytest.mark.asyncio
async def test_paginate_with_cursor_empty_data(client_api: ClientAPI) -> None:
    """Test that pagination stops when the extracted data is empty."""
    fetcher = _make_fetcher([SimpleNamespace(data=[], meta=None)])
    pages = await _collect(
        client_api._paginate_with_cursor(fetcher, {"limit": 2}, "items")
    )
    assert pages == []  # noqa: S101


# Scenario: Paginate handles a fetch error gracefully
@pytest.mark.asyncio
async def test_paginate_with_cursor_fetch_error(client_api: ClientAPI) -> None:
    """Test that pagination logs and stops when the fetcher raises."""
    fetcher = MagicMock()
    fetcher.fetch_single = AsyncMock(side_effect=RuntimeError("api down"))
    pages = await _collect(
        client_api._paginate_with_cursor(fetcher, {"limit": 2}, "items")
    )
    assert pages == []  # noqa: S101


# =====================
# Test Cases: fetch_* wrappers
# =====================


@pytest.mark.asyncio
async def test_fetch_reports(client_api: ClientAPI) -> None:
    """Test that fetch_reports paginates using the 'reports' fetcher."""
    fetcher = _make_fetcher([SimpleNamespace(data=["r1"], meta=None)])
    client_api.fetcher_factory.create_fetcher_by_name = MagicMock(return_value=fetcher)
    pages = await _collect(client_api.fetch_reports(None))
    assert pages == [["r1"]]  # noqa: S101
    client_api.fetcher_factory.create_fetcher_by_name.assert_called_with(
        "reports", base_url=client_api.config.api_url
    )


@pytest.mark.asyncio
async def test_fetch_campaigns(client_api: ClientAPI) -> None:
    """Test that fetch_campaigns paginates using the 'campaigns' fetcher."""
    fetcher = _make_fetcher([SimpleNamespace(data=["c1"], meta=None)])
    client_api.fetcher_factory.create_fetcher_by_name = MagicMock(return_value=fetcher)
    pages = await _collect(client_api.fetch_campaigns(None))
    assert pages == [["c1"]]  # noqa: S101


@pytest.mark.asyncio
async def test_fetch_threat_actors(client_api: ClientAPI) -> None:
    """Test that fetch_threat_actors paginates using the 'threat_actors_list' fetcher."""
    fetcher = _make_fetcher([SimpleNamespace(data=["ta1"], meta=None)])
    client_api.fetcher_factory.create_fetcher_by_name = MagicMock(return_value=fetcher)
    pages = await _collect(client_api.fetch_threat_actors(None))
    assert pages == [["ta1"]]  # noqa: S101


@pytest.mark.asyncio
async def test_fetch_malware_families(client_api: ClientAPI) -> None:
    """Test that fetch_malware_families paginates using the 'malware_families_list' fetcher."""
    fetcher = _make_fetcher([SimpleNamespace(data=["m1"], meta=None)])
    client_api.fetcher_factory.create_fetcher_by_name = MagicMock(return_value=fetcher)
    pages = await _collect(client_api.fetch_malware_families(None))
    assert pages == [["m1"]]  # noqa: S101


@pytest.mark.asyncio
async def test_fetch_vulnerabilities(client_api: ClientAPI) -> None:
    """Test that fetch_vulnerabilities paginates using the 'vulnerabilities_list' fetcher."""
    fetcher = _make_fetcher([SimpleNamespace(data=["v1"], meta=None)])
    client_api.fetcher_factory.create_fetcher_by_name = MagicMock(return_value=fetcher)
    pages = await _collect(client_api.fetch_vulnerabilities(None))
    assert pages == [["v1"]]  # noqa: S101


# =====================
# Test Cases: campaign subentity gathering
# =====================


@pytest.mark.asyncio
async def test_fetch_campaign_subentities_collects_list_pages(
    client_api: ClientAPI,
) -> None:
    """Test that campaign subentities are aggregated from list-shaped pages."""
    fetcher = _make_fetcher(
        [[{"id": "ta-1"}, {"id": "ta-2"}, {"no_id": True}]]
        + [None] * 8  # remaining subentity_types return nothing
    )
    client_api.fetcher_factory.create_fetcher_by_name = MagicMock(return_value=fetcher)
    result = await client_api.fetch_campaign_subentities("campaign-1")
    assert result == {"threat_actors": ["ta-1", "ta-2"]}  # noqa: S101


@pytest.mark.asyncio
async def test_fetch_campaign_subentities_collects_dict_wrapped_pages(
    client_api: ClientAPI,
) -> None:
    """Test that campaign subentities are aggregated from dict-wrapped pages."""
    fetcher = _make_fetcher([{"data": [{"id": "mw-1"}]}] + [None] * 8)
    client_api.fetcher_factory.create_fetcher_by_name = MagicMock(return_value=fetcher)
    result = await client_api.fetch_campaign_subentities("campaign-1")
    assert result == {"threat_actors": ["mw-1"]}  # noqa: S101


@pytest.mark.asyncio
async def test_fetch_campaign_subentities_swallows_per_type_error(
    client_api: ClientAPI,
) -> None:
    """Test that a failure fetching one subentity type does not abort the others."""
    fetcher = MagicMock()
    fetcher.fetch_single = AsyncMock(side_effect=RuntimeError("boom"))
    client_api.fetcher_factory.create_fetcher_by_name = MagicMock(return_value=fetcher)
    result = await client_api.fetch_campaign_subentities("campaign-1")
    assert result == {}  # noqa: S101


@pytest.mark.asyncio
async def test_fetch_campaign_subentities_relationships_fetcher_build_failure(
    client_api: ClientAPI,
) -> None:
    """Test that failing to build the relationships fetcher propagates (built outside the try block)."""
    client_api.fetcher_factory.create_fetcher_by_name = MagicMock(
        side_effect=RuntimeError("factory exploded")
    )
    with pytest.raises(RuntimeError, match="factory exploded"):
        await client_api.fetch_campaign_subentities("campaign-1")


@pytest.mark.asyncio
async def test_fetch_campaign_subentity_details(client_api: ClientAPI) -> None:
    """Test that campaign subentity details are fetched per id, skipping empty types."""
    fetcher = MagicMock()
    fetcher.fetch_single = AsyncMock(side_effect=["detail-1", None])
    client_api.fetcher_factory.create_fetcher_by_name = MagicMock(return_value=fetcher)
    subentity_ids = {"threat_actors": ["id-1", "id-2"], "malware_families": []}
    result = await client_api.fetch_campaign_subentity_details(subentity_ids)
    assert result == {"threat_actors": ["detail-1"]}  # noqa: S101


@pytest.mark.asyncio
async def test_fetch_campaign_subentity_details_swallows_per_id_error(
    client_api: ClientAPI,
) -> None:
    """Test that a failure fetching one id's details does not abort the batch."""
    fetcher = MagicMock()
    fetcher.fetch_single = AsyncMock(side_effect=[RuntimeError("boom"), "ok"])
    client_api.fetcher_factory.create_fetcher_by_name = MagicMock(return_value=fetcher)
    subentity_ids = {"threat_actors": ["id-1", "id-2"]}
    result = await client_api.fetch_campaign_subentity_details(subentity_ids)
    assert result == {"threat_actors": ["ok"]}  # noqa: S101


@pytest.mark.asyncio
async def test_fetch_campaign_subentity_details_entity_type_error(
    client_api: ClientAPI,
) -> None:
    """Test that a factory failure for one entity type is logged and skipped."""
    client_api.fetcher_factory.create_fetcher_by_name = MagicMock(
        side_effect=RuntimeError("factory exploded")
    )
    result = await client_api.fetch_campaign_subentity_details(
        {"threat_actors": ["id-1"]}
    )
    assert result == {}  # noqa: S101


# =====================
# Test Cases: report subentity gathering (fetch_subentities_ids / fetch_subentity_details)
# =====================


@pytest.mark.asyncio
async def test_fetch_subentities_ids_collects_and_logs(client_api: ClientAPI) -> None:
    """Test that report subentity IDs are aggregated across all subentity types."""
    fetcher = _make_fetcher([[{"id": "mw-1"}]] + [None] * 8)
    client_api.fetcher_factory.create_fetcher_by_name = MagicMock(return_value=fetcher)
    result = await client_api.fetch_subentities_ids("report-1")
    assert result == {"malware_families": ["mw-1"]}  # noqa: S101


@pytest.mark.asyncio
async def test_fetch_subentities_ids_relationships_fetcher_build_failure(
    client_api: ClientAPI,
) -> None:
    """Test that failing to build the relationships fetcher propagates (built outside the try block)."""
    client_api.fetcher_factory.create_fetcher_by_name = MagicMock(
        side_effect=RuntimeError("factory exploded")
    )
    with pytest.raises(RuntimeError, match="factory exploded"):
        await client_api.fetch_subentities_ids("report-1")


@pytest.mark.asyncio
async def test_fetch_subentity_details_reports_partial_and_full_fetches(
    client_api: ClientAPI,
) -> None:
    """Test that fetch_subentity_details fetches details per type via fetch_multiple."""
    fetcher = MagicMock()
    fetcher.fetch_multiple = AsyncMock(return_value=["d1"])
    client_api.fetcher_factory.create_fetcher_by_name = MagicMock(return_value=fetcher)
    result = await client_api.fetch_subentity_details(
        {"malware_families": ["id-1", "id-2"], "threat_actors": []}
    )
    assert result == {"malware_families": ["d1"], "threat_actors": []}  # noqa: S101


@pytest.mark.asyncio
async def test_fetch_subentity_details_handles_factory_error(
    client_api: ClientAPI,
) -> None:
    """Test that fetch_subentity_details logs and continues when a fetcher fails to build."""
    client_api.fetcher_factory.create_fetcher_by_name = MagicMock(
        side_effect=RuntimeError("factory exploded")
    )
    result = await client_api.fetch_subentity_details({"malware_families": ["id-1"]})
    assert result == {"malware_families": []}  # noqa: S101


# =====================
# Test Cases: observable enrichment lookups
# =====================


@pytest.mark.asyncio
async def test_fetch_observable_threat_actors_from_list_pages(
    client_api: ClientAPI,
) -> None:
    """Test extraction of threat actor names from list-shaped observable pages."""
    fetcher = _make_fetcher([[{"attributes": {"name": "APT1"}}, {"id": "apt2"}]])
    client_api.fetcher_factory.create_fetcher_by_name = MagicMock(return_value=fetcher)
    result = await client_api.fetch_observable_threat_actors("domains", "example.com")
    assert result == ["APT1", "apt2"]  # noqa: S101
    client_api.fetcher_factory.create_fetcher_by_name.assert_called_with(
        "domain_threat_actors", base_url=client_api.config.api_url
    )


@pytest.mark.asyncio
async def test_fetch_observable_threat_actors_ip_uses_ip_fetcher(
    client_api: ClientAPI,
) -> None:
    """Test that the ip_addresses observable type maps to the ip_threat_actors fetcher."""
    fetcher = _make_fetcher([None])
    client_api.fetcher_factory.create_fetcher_by_name = MagicMock(return_value=fetcher)
    await client_api.fetch_observable_threat_actors("ip_addresses", "1.2.3.4")
    client_api.fetcher_factory.create_fetcher_by_name.assert_called_with(
        "ip_threat_actors", base_url=client_api.config.api_url
    )


@pytest.mark.asyncio
async def test_fetch_observable_threat_actors_dict_wrapped_page(
    client_api: ClientAPI,
) -> None:
    """Test extraction of threat actor names from dict-wrapped observable pages."""
    fetcher = _make_fetcher([{"data": [{"attributes": {"name": "APT2"}}]}])
    client_api.fetcher_factory.create_fetcher_by_name = MagicMock(return_value=fetcher)
    result = await client_api.fetch_observable_threat_actors("files", "hash123")
    assert result == ["APT2"]  # noqa: S101


@pytest.mark.asyncio
async def test_fetch_observable_threat_actors_swallows_error(
    client_api: ClientAPI,
) -> None:
    """Test that observable threat actor lookup returns an empty list on error."""
    client_api.fetcher_factory.create_fetcher_by_name = MagicMock(
        side_effect=RuntimeError("boom")
    )
    result = await client_api.fetch_observable_threat_actors("urls", "url-1")
    assert result == []  # noqa: S101


@pytest.mark.asyncio
async def test_fetch_observable_malware_from_list_pages(client_api: ClientAPI) -> None:
    """Test extraction of malware family names from list-shaped observable pages."""
    fetcher = _make_fetcher([[{"attributes": {"name": "Emotet"}}, {"id": "trickbot"}]])
    client_api.fetcher_factory.create_fetcher_by_name = MagicMock(return_value=fetcher)
    result = await client_api.fetch_observable_malware("domains", "example.com")
    assert result == ["Emotet", "trickbot"]  # noqa: S101
    client_api.fetcher_factory.create_fetcher_by_name.assert_called_with(
        "domain_collections", base_url=client_api.config.api_url
    )


@pytest.mark.asyncio
async def test_fetch_observable_malware_ip_uses_ip_fetcher(
    client_api: ClientAPI,
) -> None:
    """Test that the ip_addresses observable type maps to the ip_collections fetcher."""
    fetcher = _make_fetcher([None])
    client_api.fetcher_factory.create_fetcher_by_name = MagicMock(return_value=fetcher)
    await client_api.fetch_observable_malware("ip_addresses", "1.2.3.4")
    client_api.fetcher_factory.create_fetcher_by_name.assert_called_with(
        "ip_collections", base_url=client_api.config.api_url
    )


@pytest.mark.asyncio
async def test_fetch_observable_malware_dict_wrapped_page(
    client_api: ClientAPI,
) -> None:
    """Test extraction of malware family names from dict-wrapped observable pages."""
    fetcher = _make_fetcher([{"data": [{"id": "qakbot"}]}])
    client_api.fetcher_factory.create_fetcher_by_name = MagicMock(return_value=fetcher)
    result = await client_api.fetch_observable_malware("files", "hash123")
    assert result == ["qakbot"]  # noqa: S101


@pytest.mark.asyncio
async def test_fetch_observable_malware_swallows_error(client_api: ClientAPI) -> None:
    """Test that observable malware lookup returns an empty list on error."""
    client_api.fetcher_factory.create_fetcher_by_name = MagicMock(
        side_effect=RuntimeError("boom")
    )
    result = await client_api.fetch_observable_malware("urls", "url-1")
    assert result == []  # noqa: S101
