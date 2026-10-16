from datetime import date, datetime, timezone

import pytest
from conftest import JARM, SEARCH_URL, scout_ip
from connectors_sdk.connectors.internal_hunt import HuntExecutionError, RunDeadline
from cymru_scout_hunt.client import ScoutClient

API_URL = "https://scout.cymru.com/api/scout"
START = date(2026, 10, 3)
END = date(2026, 10, 4)


@pytest.fixture
def deadline() -> RunDeadline:
    return RunDeadline(30)


def test_search_maps_the_ip_addresses_and_keeps_the_total(requests_mock, deadline):
    # Given two IP addresses out of 40, and an entry without address
    requests_mock.get(
        SEARCH_URL,
        json={"total": 40, "ips": [scout_ip(), scout_ip("1.1.1.1"), {"summary": {}}]},
    )

    # When searching
    result = ScoutClient(API_URL, "key").search(
        'fingerprints.hash = "x"', START, END, 10000, deadline
    )

    # Then the search covers the days with the largest page, and the total tells more matches exist
    request = requests_mock.last_request
    assert request.headers["Authorization"] == "Token key"
    assert request.qs == {
        "query": ['fingerprints.hash = "x"'],
        "start_date": ["2026-10-03"],
        "end_date": ["2026-10-04"],
        "size": ["5000"],
    }
    assert (result.total, result.read, result.truncated) == (40, 3, True)
    first, second = result.hosts
    assert first.asn == 20473 and first.as_name == "AS-CHOOPA"
    assert first.domains == ["c2.update-cdn.net"] and first.ports == [443]
    assert first.fingerprints == {"jarm": [JARM]}
    assert first.tags == ["malware", "cobalt-strike"]
    assert first.last_seen == datetime(2026, 10, 3, tzinfo=timezone.utc)
    assert second.ip == "1.1.1.1"


@pytest.mark.parametrize(
    ("ips", "truncated"),
    [
        pytest.param(3, True, id="full_page"),
        pytest.param(1, False, id="short_page"),
    ],
)
def test_without_total_a_full_page_may_leave_matches(
    requests_mock, deadline, ips, truncated
):
    # Given an answer without total
    requests_mock.get(
        SEARCH_URL, json={"ips": [scout_ip(f"8.8.8.{n}") for n in range(ips)]}
    )

    # When searching with a limit of two IP addresses
    result = ScoutClient(API_URL, "key").search(JARM, START, END, 2, deadline)

    # Then a full page truncates the result
    assert requests_mock.last_request.qs["size"] == ["2"]
    assert result.truncated is truncated


def test_unexpected_answers_fail(requests_mock, deadline):
    requests_mock.get(SEARCH_URL, json=["x"])
    with pytest.raises(HuntExecutionError, match="unexpected answer"):
        ScoutClient(API_URL, "key").search("q", START, END, 5, deadline)
