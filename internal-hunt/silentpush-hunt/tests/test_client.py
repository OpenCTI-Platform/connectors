import pytest
from conftest import SEARCH_URL, scan, scans_answer
from connectors_sdk.connectors.internal_hunt import HuntExecutionError, RunDeadline
from silentpush_hunt.client import SilentPushClient

API_URL = "https://api.silentpush.com"


@pytest.fixture
def deadline() -> RunDeadline:
    return RunDeadline(30)


def test_search_pages_with_skip(requests_mock, deadline):
    # Given a full page of scans, then a short one with unusable scans
    requests_mock.post(
        SEARCH_URL,
        [
            {"json": scans_answer([scan()] * 1000)},
            {"json": scans_answer([{"port": 1}, {"ip": "1.1.1.1"}])},
        ],
    )
    client = SilentPushClient(API_URL, "key")

    # When searching
    result = client.search('jarm = "x"', 1500, deadline)

    # Then both pages are read with the API key, and the short page ends the results
    first, second = requests_mock.request_history
    assert first.headers["X-API-Key"] == "key"
    assert first.qs == {"limit": ["1000"], "skip": ["0"]}
    assert first.json() == {"query": 'jarm = "x"'}
    assert second.qs == {"limit": ["500"], "skip": ["1000"]}
    assert len(result.hosts) == 1001 and result.total is None
    assert (result.read, result.requests, result.truncated) == (1002, 2, False)
    host = result.hosts[0]
    assert host.domains == ["c2.update-cdn.net", "update-cdn.net"]
    assert host.certificates[0].subject == "CN=update-cdn.net"
    assert host.fingerprints["http.server"] == ["nginx"]
    assert host.urls == ["https://c2.update-cdn.net/"]


def test_reading_up_to_the_limit_may_leave_matches(requests_mock, deadline):
    # Given more scans than the limit
    requests_mock.post(
        SEARCH_URL, json=scans_answer([{"ip": "8.8.8.8", "ssl": {}}] * 3)
    )
    client = SilentPushClient(API_URL, "key")

    # When searching with a limit of two scans
    result = client.search("q", 2, deadline)

    # Then one page is read and the result is truncated
    assert requests_mock.call_count == 1
    assert len(result.hosts) == 2 and result.hosts[0].certificates == []
    assert result.truncated is True


def test_unexpected_answers_fail(requests_mock, deadline):
    requests_mock.post(SEARCH_URL, json=["x"])
    with pytest.raises(HuntExecutionError, match="unexpected answer"):
        SilentPushClient(API_URL, "key").search("q", 5, deadline)
