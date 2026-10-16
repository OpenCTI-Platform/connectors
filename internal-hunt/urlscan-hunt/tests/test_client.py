from datetime import date

import pytest
from conftest import SEARCH_URL, scan
from connectors_sdk.connectors.internal_hunt import HuntExecutionError, RunDeadline
from urlscan_hunt.client import UrlscanClient

API_URL = "https://urlscan.io"
START = date(2026, 10, 3)
END = date(2026, 10, 4)


@pytest.fixture
def deadline() -> RunDeadline:
    return RunDeadline(30)


def test_search_dates_the_query_and_follows_search_after(requests_mock, deadline):
    # Given two pages of scans, the second holding a scan without page
    requests_mock.get(
        SEARCH_URL,
        [
            {"json": {"results": [scan()], "total": 3, "has_more": True}},
            {"json": {"results": [{"page": {}}, scan()], "total": 3}},
        ],
    )
    client = UrlscanClient(API_URL, "key")

    # When searching
    result = client.search('page.title:"Login"', START, END, 10, deadline)

    # Then the query is bounded by the days, and the second page follows the sort values
    first, second = requests_mock.request_history
    assert first.headers["API-Key"] == "key"
    assert first.qs["q"] == ['(page.title:"login") and date:[2026-10-03 to 2026-10-04]']
    assert first.qs["size"] == ["10"]
    assert second.qs["search_after"] == ["1759478400000,abc"]
    assert second.qs["size"] == ["9"]
    # The day-bounded total is not a hit count of the run window; every match was read
    assert (result.total, result.truncated) == (None, False)
    assert (len(result.hosts), result.read, result.requests) == (2, 3, 2)
    host = result.hosts[0]
    assert host.asn == 20473 and host.as_name == "AS-CHOOPA"
    assert host.fingerprints == {
        "http.title": ["Sign in to your account"],
        "http.server": ["nginx"],
        "certificate.issuer": ["R3"],
    }
    assert host.urls == ["https://login.update-cdn.net/login"]


@pytest.mark.parametrize(
    ("answer", "read"),
    [
        pytest.param(
            {"results": [{"page": {"ip": "8.8.8.8"}}], "has_more": True},
            1,
            id="more_without_cursor",
        ),
        pytest.param(
            {"results": [{"page": {"ip": "8.8.8.8"}}], "total": 40},
            1,
            id="total_beyond_the_scans_read",
        ),
    ],
)
def test_matches_left_unread_truncate_the_result(requests_mock, deadline, answer, read):
    # Given an answer telling that more scans match
    requests_mock.get(SEARCH_URL, json=answer)

    # When searching
    result = UrlscanClient(API_URL, "key").search("q", START, END, 10, deadline)

    # Then one page is read and the result is truncated
    assert requests_mock.call_count == 1
    assert (result.read, result.truncated) == (read, True)


def test_unexpected_answers_fail(requests_mock, deadline):
    requests_mock.get(SEARCH_URL, json=["x"])
    with pytest.raises(HuntExecutionError, match="unexpected answer"):
        UrlscanClient(API_URL, "key").search("q", START, END, 5, deadline)
