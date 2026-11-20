from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from src.services.client.cpe_match import CPEMatchClient
from src.services.converter.vulnerability_to_stix2 import CVEConverter
from src.services.utils.rate_limiter import AsyncRateLimiter

from tests.conftest import make_cpe_name, make_vulnerability
from tests.tests_connector.test_api_client import _build_context_manager_response


def test_extract_cpe_names_ignores_criteria_patterns():
    data = {
        "matchStrings": [
            {
                "matchString": {
                    "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                    "matches": [],
                }
            }
        ]
    }
    cpe_names: set[str] = set()

    CPEMatchClient._extract_cpe_names(data, cpe_names)

    assert cpe_names == set()


def test_extract_cpe_names_filters_invalid_values():
    valid_cpe = "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
    data = {
        "matchStrings": [
            {
                "matchString": {
                    "matches": [
                        {"cpeName": None},
                        {"cpeName": ""},
                        {"cpeName": "   "},
                        {"cpeName": 123},
                        {},
                        {"cpeName": valid_cpe},
                    ]
                }
            }
        ]
    }
    cpe_names: set[str] = set()

    CPEMatchClient._extract_cpe_names(data, cpe_names)

    assert cpe_names == {valid_cpe}


async def test_get_cpes_for_cve_stops_when_initial_results_per_page_is_zero():
    valid_cpe = "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
    first_page = {
        "totalResults": 10,
        "resultsPerPage": 0,
        "matchStrings": [{"matchString": {"matches": [{"cpeName": valid_cpe}]}}],
    }

    client = CPEMatchClient.__new__(CPEMatchClient)
    client.helper = MagicMock()
    client.helper.connector_logger = MagicMock()
    client.get_complete_collection = AsyncMock(return_value=first_page)

    result = await client.get_cpes_for_cve("CVE-2024-0001")

    assert result == [valid_cpe]
    assert client.get_complete_collection.await_count == 1


async def test_get_cpes_for_cve_stops_when_paginated_results_per_page_is_zero():
    cpe1 = "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
    cpe2 = "cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*"
    first_page = {
        "totalResults": 4,
        "resultsPerPage": 2,
        "matchStrings": [{"matchString": {"matches": [{"cpeName": cpe1}]}}],
    }
    second_page = {
        "totalResults": 4,
        "resultsPerPage": 0,
        "matchStrings": [{"matchString": {"matches": [{"cpeName": cpe2}]}}],
    }

    client = CPEMatchClient.__new__(CPEMatchClient)
    client.helper = MagicMock()
    client.helper.connector_logger = MagicMock()
    client.get_complete_collection = AsyncMock(side_effect=[first_page, second_page])

    result = await client.get_cpes_for_cve("CVE-2024-0002")

    assert set(result) == {cpe1, cpe2}
    assert client.get_complete_collection.await_count == 2


DATE_KEYS = {"lastModStartDate", "lastModEndDate"}


def _match_string(
    cpe_name: str,
    last_modified: str | None = None,
    cpe_last_modified: str | None = None,
) -> dict:
    match_string: dict = {"matches": [{"cpeName": cpe_name}]}
    if last_modified is not None:
        match_string["lastModified"] = last_modified
    if cpe_last_modified is not None:
        match_string["cpeLastModified"] = cpe_last_modified
    return {"matchString": match_string}


async def test_converter_never_sends_last_mod_dates_with_cve_id():
    """#8308: NVD answers 500 on cveId + lastModStartDate/lastModEndDate.

    Even with cpe_history_interval set, every request (first and later page)
    must carry cveId only, plus pagination.
    """
    recent = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
    cpe1 = make_cpe_name(product="one")
    cpe2 = make_cpe_name(product="two")
    first_page = {
        "totalResults": 3,
        "resultsPerPage": 2,
        "matchStrings": [
            _match_string(cpe1, recent),
            # Older than cpe_history_interval: must be dropped client-side.
            _match_string(make_cpe_name(product="old"), "2001-01-01T00:00:00.000"),
        ],
    }
    second_page = {
        "totalResults": 3,
        "resultsPerPage": 2,
        "matchStrings": [_match_string(cpe2, recent)],
    }

    client = CPEMatchClient.__new__(CPEMatchClient)
    client.helper = MagicMock()
    client.get_complete_collection = AsyncMock(side_effect=[first_page, second_page])

    converter = CVEConverter.__new__(CVEConverter)
    converter.helper = MagicMock()
    converter.cpe_history_interval = timedelta(days=120)
    converter.author = CVEConverter._create_author()
    converter.cpe_match_client = client

    cve_id = "CVE-2024-0003"
    vuln_stix = MagicMock()
    vuln_stix.id = "vulnerability--00000000-0000-4000-8000-000000000000"
    objects = await converter._resolve_cpes_for_vulnerability(
        make_vulnerability(cve_id), vuln_stix
    )

    assert client.get_complete_collection.await_count == 2
    for call in client.get_complete_collection.await_args_list:
        params = call.args[1]
        assert params["cveId"] == cve_id
        assert DATE_KEYS.isdisjoint(params)
    assert len([o for o in objects if o.type == "software"]) == 2


def test_extract_cpe_names_window_keeps_match_strings_modified_since():
    """#8308: the history window is applied client-side on lastModified."""
    inside = make_cpe_name(product="inside")
    outside = make_cpe_name(product="outside")
    data = {
        "matchStrings": [
            _match_string(inside, "2024-06-15T00:00:00.000"),
            _match_string(outside, "2024-05-31T23:59:59.999"),
        ]
    }
    cpe_names: set[str] = set()

    CPEMatchClient._extract_cpe_names(
        data, cpe_names, datetime(2024, 6, 1, tzinfo=timezone.utc)
    )

    assert cpe_names == {inside}


def test_extract_cpe_names_window_handles_nvd_naive_and_offset_formats():
    """#8308: NVD naive timestamps are UTC, offset-aware ones are honoured."""
    naive_in = make_cpe_name(product="naive_in")
    naive_out = make_cpe_name(product="naive_out")
    offset_in = make_cpe_name(product="offset_in")
    offset_out = make_cpe_name(product="offset_out")
    data = {
        "matchStrings": [
            _match_string(naive_in, "2023-02-09T19:31:01.650"),
            _match_string(naive_out, "2023-02-09T19:30:59.000"),
            # 19:31:00 UTC once converted
            _match_string(offset_in, "2023-02-09T20:31:00.000+01:00"),
            # 19:00:00 UTC once converted
            _match_string(offset_out, "2023-02-09T20:00:00.000+01:00"),
        ]
    }
    cpe_names: set[str] = set()

    CPEMatchClient._extract_cpe_names(
        data, cpe_names, datetime(2023, 2, 9, 19, 31, 0, tzinfo=timezone.utc)
    )

    assert cpe_names == {naive_in, offset_in}


def test_extract_cpe_names_window_keeps_missing_or_unparseable_last_modified():
    """#8308: a match string without a usable lastModified is kept (fail open)."""
    missing = make_cpe_name(product="missing")
    garbage = make_cpe_name(product="garbage")
    not_a_string = make_cpe_name(product="not_a_string")
    data = {
        "matchStrings": [
            _match_string(missing),
            _match_string(garbage, "not-a-date"),
            _match_string(not_a_string, 20240101),  # type: ignore[arg-type]
        ]
    }
    cpe_names: set[str] = set()

    CPEMatchClient._extract_cpe_names(
        data, cpe_names, datetime(2030, 1, 1, tzinfo=timezone.utc)
    )

    assert cpe_names == {missing, garbage, not_a_string}


def test_extract_cpe_names_window_uses_most_recent_of_both_dates():
    """#8308: the more recent of lastModified and cpeLastModified is compared."""
    old = "2024-01-01T00:00:00.000"
    recent = "2024-07-01T00:00:00.000"
    old_match_recent_cpe = make_cpe_name(product="old_match_recent_cpe")
    recent_match_old_cpe = make_cpe_name(product="recent_match_old_cpe")
    recent_match_no_cpe = make_cpe_name(product="recent_match_no_cpe")
    both_old = make_cpe_name(product="both_old")
    old_match_no_cpe = make_cpe_name(product="old_match_no_cpe")
    data = {
        "matchStrings": [
            _match_string(old_match_recent_cpe, old, recent),
            _match_string(recent_match_old_cpe, recent, old),
            _match_string(recent_match_no_cpe, recent),
            _match_string(both_old, old, old),
            _match_string(old_match_no_cpe, old),
        ]
    }
    cpe_names: set[str] = set()

    CPEMatchClient._extract_cpe_names(
        data, cpe_names, datetime(2024, 6, 1, tzinfo=timezone.utc)
    )

    assert cpe_names == {
        old_match_recent_cpe,
        recent_match_old_cpe,
        recent_match_no_cpe,
    }


def test_extract_cpe_names_window_ignores_unparseable_field_but_uses_the_other():
    """#8308: an unparseable date is ignored, the other one still decides."""
    recent_cpe = make_cpe_name(product="recent_cpe")
    old_cpe = make_cpe_name(product="old_cpe")
    data = {
        "matchStrings": [
            _match_string(recent_cpe, "not-a-date", "2024-07-01T00:00:00.000"),
            _match_string(old_cpe, "not-a-date", "2024-01-01T00:00:00.000"),
        ]
    }
    cpe_names: set[str] = set()

    CPEMatchClient._extract_cpe_names(
        data, cpe_names, datetime(2024, 6, 1, tzinfo=timezone.utc)
    )

    assert cpe_names == {recent_cpe}


def test_extract_cpe_names_window_keeps_match_string_when_no_date_parses():
    """#8308: fail open when neither date is usable."""
    both_garbage = make_cpe_name(product="both_garbage")
    data = {"matchStrings": [_match_string(both_garbage, "nope", "also-nope")]}
    cpe_names: set[str] = set()

    CPEMatchClient._extract_cpe_names(
        data, cpe_names, datetime(2030, 1, 1, tzinfo=timezone.utc)
    )

    assert cpe_names == {both_garbage}


def test_extract_cpe_names_without_modified_since_keeps_everything():
    """#8308: no window (modified_since=None) means no filtering."""
    old = make_cpe_name(product="old")
    recent = make_cpe_name(product="recent")
    data = {
        "matchStrings": [
            _match_string(old, "2001-01-01T00:00:00.000"),
            _match_string(recent, "2099-01-01T00:00:00.000"),
        ]
    }
    cpe_names: set[str] = set()

    CPEMatchClient._extract_cpe_names(data, cpe_names)

    assert cpe_names == {old, recent}


async def test_get_cpes_for_cve_applies_window_on_every_page():
    """#8308: modified_since is applied to the first and the later pages."""
    cutoff = datetime(2024, 6, 1, tzinfo=timezone.utc)
    first_in = make_cpe_name(product="first_in")
    first_out = make_cpe_name(product="first_out")
    second_in = make_cpe_name(product="second_in")
    second_out = make_cpe_name(product="second_out")
    first_page = {
        "totalResults": 4,
        "resultsPerPage": 2,
        "matchStrings": [
            _match_string(first_in, "2024-07-01T00:00:00.000"),
            _match_string(first_out, "2024-01-01T00:00:00.000"),
        ],
    }
    second_page = {
        "totalResults": 4,
        "resultsPerPage": 2,
        "matchStrings": [
            _match_string(second_in, "2024-08-01T00:00:00.000"),
            _match_string(second_out, "2024-02-01T00:00:00.000"),
        ],
    }

    client = CPEMatchClient.__new__(CPEMatchClient)
    client.helper = MagicMock()
    client.get_complete_collection = AsyncMock(side_effect=[first_page, second_page])

    result = await client.get_cpes_for_cve("CVE-2024-0004", cutoff)

    assert set(result) == {first_in, second_in}
    for call in client.get_complete_collection.await_args_list:
        assert DATE_KEYS.isdisjoint(call.args[1])


async def test_get_cpes_for_cve_warns_with_final_error_when_nvd_keeps_failing():
    """#8308: the final HTTP error is logged as a warning, not swallowed at DEBUG."""
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    client = CPEMatchClient(
        api_key="fake-key",
        helper=helper,
        header="test/1.0",
        rate_limiter=AsyncRateLimiter(),
    )
    session = MagicMock()
    session.closed = False
    session.get = MagicMock(
        side_effect=lambda *a, **kw: _build_context_manager_response(
            status=500, json_body={"message": "Internal Server Error"}
        )
    )

    with (
        patch.object(client, "_get_session", AsyncMock(return_value=session)),
        patch("src.services.client.api.asyncio.sleep", AsyncMock()),
    ):
        result = await client.get_cpes_for_cve("CVE-2024-0005")

    assert result == []
    assert session.get.call_count == 5
    warnings = [
        call
        for call in helper.connector_logger.warning.call_args_list
        if call.kwargs.get("meta", {}).get("cve_id") == "CVE-2024-0005"
    ]
    assert len(warnings) == 1
    meta = warnings[0].kwargs["meta"]
    assert "500" in meta["error"]
    assert "Internal Server Error" in meta["error"]


async def test_get_cpes_for_cve_warns_and_keeps_first_page_when_later_page_fails():
    """#8308: a failed later page is logged and keeps the CPEs already collected."""
    cpe1 = make_cpe_name(product="one")
    first_page = {
        "totalResults": 4,
        "resultsPerPage": 2,
        "matchStrings": [_match_string(cpe1)],
    }

    client = CPEMatchClient.__new__(CPEMatchClient)
    client.helper = MagicMock()
    client.helper.connector_logger = MagicMock()
    client._last_error = "[API] Request failed with status 500: Internal Server Error"
    client.get_complete_collection = AsyncMock(side_effect=[first_page, None])

    result = await client.get_cpes_for_cve("CVE-2024-0006")

    assert result == [cpe1]
    client.helper.connector_logger.warning.assert_called_once()
    meta = client.helper.connector_logger.warning.call_args.kwargs["meta"]
    assert meta == {
        "cve_id": "CVE-2024-0006",
        "start_index": 2,
        "error": client._last_error,
    }


async def test_get_cpes_for_cve_warning_names_exception_with_empty_message():
    """#8308: an exception with an empty str() still yields a non-empty error."""
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    client = CPEMatchClient(
        api_key="fake-key",
        helper=helper,
        header="test/1.0",
        rate_limiter=AsyncRateLimiter(),
    )

    with patch.object(client, "request", AsyncMock(side_effect=AssertionError())):
        result = await client.get_cpes_for_cve("CVE-2024-0007")

    assert result == []
    assert client._last_error == "AssertionError()"
    helper.connector_logger.warning.assert_called_once()
    meta = helper.connector_logger.warning.call_args.kwargs["meta"]
    assert meta["cve_id"] == "CVE-2024-0007"
    assert "AssertionError" in meta["error"]
