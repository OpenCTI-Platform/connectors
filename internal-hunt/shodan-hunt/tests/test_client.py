from datetime import datetime, timezone

import pytest
import requests
from conftest import CERT_SHA256, CERT_SUBJECT, JARM, SEARCH_URL, banner
from connectors_sdk.connectors.internal_hunt import (
    HuntExecutionError,
    HuntTimeoutError,
    RunDeadline,
)
from shodan_hunt.client import ShodanClient, distinguished_name

API_URL = "https://api.shodan.io"
KEY = "shodan-secret-key"


@pytest.fixture
def deadline() -> RunDeadline:
    return RunDeadline(30)


def test_search_reads_every_page(requests_mock, deadline):
    # Given a full page of banners, then a short one with a banner without address
    requests_mock.get(
        SEARCH_URL,
        [
            {"json": {"total": 150, "matches": [banner(port=p) for p in range(100)]}},
            {"json": {"total": 150, "matches": [banner("1.1.1.1"), {"port": 1}]}},
        ],
    )

    # When searching
    result = ShodanClient(API_URL, KEY).search('ssl.jarm:"x"', 1000, deadline)

    # Then both pages are read with the key, one banner per service
    first, second = requests_mock.request_history
    assert first.qs == {"key": [KEY], "query": ['ssl.jarm:"x"'], "page": ["1"]}
    assert second.qs["page"] == ["2"]
    assert (result.total, result.read, result.requests) == (150, 102, 2)
    assert len(result.hosts) == 101
    host = result.hosts[0]
    assert host.key == "8.8.8.8" and host.asn == 20473 and host.ports == [0]
    assert host.domains == ["c2.update-cdn.net", "update-cdn.net"]
    assert host.certificates[0].sha256 == CERT_SHA256
    assert host.certificates[0].subject == CERT_SUBJECT
    assert host.certificates[0].issuer == ("CN=Major Cobalt Strike, emailAddress=x@y.z")
    assert host.fingerprints == {
        "http.title": ["Not Found"],
        "http.server": ["nginx"],
        "jarm": [JARM],
    }
    assert host.tags == ["self-signed"]
    assert host.last_seen == datetime(2026, 10, 3, 8, 0, 0, 123456, timezone.utc)


def test_search_stops_at_the_limit(requests_mock, deadline):
    # Given a full page of banners
    requests_mock.get(SEARCH_URL, json={"total": 500, "matches": [banner()] * 100})

    # When searching with a limit of ten banners
    result = ShodanClient(API_URL, KEY).search("q", 10, deadline)

    # Then one page is read and the result is truncated
    assert requests_mock.call_count == 1
    assert (result.read, result.requests, result.truncated) == (10, 1, True)


def test_search_stops_when_every_match_was_read(requests_mock, deadline):
    # Given a full page holding every match
    requests_mock.get(SEARCH_URL, json={"total": 100, "matches": [banner()] * 100})

    # When searching
    result = ShodanClient(API_URL, KEY).search("q", 1000, deadline)

    # Then no empty page is requested
    assert requests_mock.call_count == 1
    assert result.truncated is False


@pytest.mark.parametrize(
    ("exc", "error"),
    [
        pytest.param(
            requests.exceptions.ConnectionError, HuntExecutionError, id="network"
        ),
        pytest.param(requests.exceptions.ReadTimeout, HuntTimeoutError, id="timeout"),
    ],
)
def test_network_errors_never_show_the_key(requests_mock, deadline, exc, error):
    # Given a network failure whose message carries the URL
    requests_mock.get(
        SEARCH_URL,
        exc=exc(f"Max retries exceeded with url: /shodan/host/search?key={KEY}"),
    )
    client = ShodanClient(API_URL, KEY)
    client._hunt_max_retries = 0

    # When/Then the hunt error hides the key
    with pytest.raises(error) as raised:
        client.search("q", 10, deadline)
    messages = f"{raised.value} {raised.value.__cause__}"
    assert KEY not in messages


def test_unexpected_answers_fail(requests_mock, deadline):
    requests_mock.get(SEARCH_URL, json=["x"])
    with pytest.raises(HuntExecutionError, match="unexpected answer"):
        ShodanClient(API_URL, KEY).search("q", 5, deadline)


def test_distinguished_name():
    # Given/When/Then the attributes are ordered like a certificate shows them
    assert distinguished_name({"C": "US", "CN": "x", "O": ""}) == "CN=x, C=US"
    assert distinguished_name(None) is None
