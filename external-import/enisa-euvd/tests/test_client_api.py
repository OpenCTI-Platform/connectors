"""Tests for `enisa_euvd.client_api.EnisaEuvdClient`."""

from datetime import datetime, timezone
from unittest.mock import patch

import pytest
import requests
from connectors_sdk import ApiServerError
from connectors_sdk.exceptions.error import DataRetrievalError
from enisa_euvd.client_api import PAGE_SIZE, USER_AGENT, EnisaEuvdClient
from enisa_euvd.models import EUVDInvalidItem, EUVDVulnerability


def _client(logger) -> EnisaEuvdClient:
    return EnisaEuvdClient(
        base_url="https://euvdservices.enisa.europa.eu/api", logger=logger
    )


def test_session_headers_include_a_descriptive_user_agent(fake_logger):
    client = _client(fake_logger)
    assert client.session_headers["User-Agent"] == USER_AGENT


def test_iter_vulnerabilities_stops_on_short_page(fake_logger, search_page):
    client = _client(fake_logger)
    with patch.object(client, "_get", return_value=search_page) as mocked_get:
        pages = list(client.iter_vulnerabilities())

    assert len(pages) == 1
    assert len(pages[0]) == 3
    assert all(isinstance(v, EUVDVulnerability) for v in pages[0])
    mocked_get.assert_called_once_with("/search", params={"page": 0, "size": PAGE_SIZE})


def test_iter_vulnerabilities_stops_on_empty_page(fake_logger, search_page_empty):
    client = _client(fake_logger)
    with patch.object(client, "_get", return_value=search_page_empty):
        pages = list(client.iter_vulnerabilities())

    assert pages == []


def test_iter_vulnerabilities_paginates_until_short_page(fake_logger, search_page):
    client = _client(fake_logger)
    full_page = {
        "items": [search_page["items"][0]] * PAGE_SIZE,
        "total": PAGE_SIZE + 1,
    }
    short_page = {"items": [search_page["items"][1]], "total": PAGE_SIZE + 1}
    with patch.object(client, "_get", side_effect=[full_page, short_page]) as mocked:
        pages = list(client.iter_vulnerabilities())

    assert len(pages) == 2
    assert len(pages[0]) == PAGE_SIZE
    assert len(pages[1]) == 1
    assert mocked.call_args_list[0].kwargs["params"] == {"page": 0, "size": PAGE_SIZE}
    assert mocked.call_args_list[1].kwargs["params"] == {"page": 1, "size": PAGE_SIZE}


def test_iter_vulnerabilities_stops_at_cutoff_since_pages_are_sorted_desc(
    fake_logger, search_page
):
    """Once an item older than the cutoff is seen, later pages are skipped.

    `/search` sorts by `dateUpdated` descending (verified against the live
    API), so encountering one item at/older than the cutoff means every
    following item -- on this page and any subsequent one -- is older too.
    """
    client = _client(fake_logger)
    # Cutoff between item[1] (Jan 14) and item[2] (Jan 13): only items[0:2]
    # are newer-or-equal, item[2] is older and must trigger an early stop.
    cutoff = datetime(2024, 1, 14, 0, 0, 0, tzinfo=timezone.utc)

    with patch.object(client, "_get", return_value=search_page) as mocked_get:
        pages = list(client.iter_vulnerabilities(updated_after=cutoff))

    assert len(pages) == 1
    assert [v.id for v in pages[0]] == ["EUVD-2024-00001", "EUVD-2024-00002"]
    mocked_get.assert_called_once()  # never fetched a second page


def test_iter_vulnerabilities_skips_malformed_items_and_keeps_valid_ones(
    fake_logger, search_page
):
    client = _client(fake_logger)
    broken_page = {
        "items": [search_page["items"][0], {"id": "EUVD-BROKEN"}],  # missing fields
        "total": 2,
    }
    with patch.object(client, "_get", return_value=broken_page):
        pages = list(client.iter_vulnerabilities())

    assert len(pages) == 1
    assert [v.id for v in pages[0]] == ["EUVD-2024-00001"]


def test_iter_vulnerabilities_skips_non_dict_items_without_crashing(fake_logger):
    client = _client(fake_logger)
    broken_page = {"items": ["not-a-dict", None, 42], "total": 3}
    with patch.object(client, "_get", return_value=broken_page):
        pages = list(client.iter_vulnerabilities())

    assert pages == []


def test_iter_vulnerabilities_accepts_a_naive_cutoff_as_utc(fake_logger, search_page):
    client = _client(fake_logger)
    naive_cutoff = datetime(2024, 1, 14, 0, 0, 0)  # no tzinfo

    with patch.object(client, "_get", return_value=search_page):
        pages = list(client.iter_vulnerabilities(updated_after=naive_cutoff))

    assert len(pages) == 1
    assert [v.id for v in pages[0]] == ["EUVD-2024-00001", "EUVD-2024-00002"]


def test_iter_vulnerabilities_coalesces_null_items_to_empty_page(fake_logger):
    client = _client(fake_logger)
    with patch.object(client, "_get", return_value={"items": None, "total": 0}):
        pages = list(client.iter_vulnerabilities())

    assert pages == []


def test_iter_vulnerabilities_excludes_items_updated_exactly_at_the_watermark(
    fake_logger, search_page
):
    """Regression test: the watermark is the newest `dateUpdated` of the
    previous run. An inclusive comparison sent that item again on every run.
    """
    client = _client(fake_logger)
    watermark = datetime(2024, 1, 15, 15, 30, 0, tzinfo=timezone.utc)  # item[0]

    with patch.object(client, "_get", return_value=search_page) as mocked_get:
        pages = list(client.iter_vulnerabilities(updated_after=watermark))

    assert pages == []
    mocked_get.assert_called_once()


def test_iter_vulnerabilities_sends_server_side_filters(fake_logger, search_page):
    client = _client(fake_logger)
    updated_after = datetime(2024, 1, 14, 23, 0, 0, tzinfo=timezone.utc)

    with patch.object(client, "_get", return_value=search_page) as mocked_get:
        list(
            client.iter_vulnerabilities(
                updated_after=updated_after, min_score=9.0, exploited_only=True
            )
        )

    mocked_get.assert_called_once_with(
        "/search",
        params={
            "size": PAGE_SIZE,
            "page": 0,
            "fromUpdatedDate": "2024-01-14",
            "fromScore": 9.0,
            "exploited": "true",
        },
    )


def test_iter_vulnerabilities_sends_no_filter_by_default(fake_logger, search_page):
    client = _client(fake_logger)

    with patch.object(client, "_get", return_value=search_page) as mocked_get:
        list(client.iter_vulnerabilities())

    mocked_get.assert_called_once_with("/search", params={"size": PAGE_SIZE, "page": 0})


@pytest.mark.parametrize(
    "error",
    [
        ApiServerError("Server error", status_code=503),
        requests.ConnectionError("Connection refused"),
    ],
)
def test_iter_vulnerabilities_raises_data_retrieval_error_when_api_unavailable(
    fake_logger, error
):
    client = _client(fake_logger)

    with patch.object(client, "_get", side_effect=error):
        with pytest.raises(DataRetrievalError, match="page 0") as exc_info:
            list(client.iter_vulnerabilities())

    assert exc_info.value.__cause__ is error


def test_iter_vulnerabilities_returns_invalid_items_with_their_date(
    fake_logger, search_page
):
    """An item failing validation is kept as an `EUVDInvalidItem`, so the
    processor can keep the watermark below it.
    """
    client = _client(fake_logger)
    invalid = {
        "id": "EUVD-2024-00099",
        "dateUpdated": "Jan 14, 2024, 9:00:00 PM",
        "description": None,
    }
    page = {
        "items": [search_page["items"][0], invalid, search_page["items"][1]],
        "total": 3,
    }
    with patch.object(client, "_get", return_value=page):
        (items,) = list(client.iter_vulnerabilities())

    assert [type(i) for i in items] == [
        EUVDVulnerability,
        EUVDInvalidItem,
        EUVDVulnerability,
    ]
    assert items[1].id == "EUVD-2024-00099"
    assert items[1].date_updated == datetime(2024, 1, 14, 21, 0, tzinfo=timezone.utc)
    assert "description" in items[1].error


def test_iter_vulnerabilities_stops_at_an_invalid_item_older_than_the_watermark(
    fake_logger, search_page
):
    client = _client(fake_logger)
    invalid = {"id": "EUVD-2024-00099", "dateUpdated": "Jan 13, 2024, 9:00:00 PM"}
    page = {"items": [search_page["items"][0], invalid], "total": 2}
    watermark = datetime(2024, 1, 14, tzinfo=timezone.utc)

    with patch.object(client, "_get", return_value=page):
        pages = list(client.iter_vulnerabilities(updated_after=watermark))

    assert [[i.id for i in p] for p in pages] == [["EUVD-2024-00001"]]
