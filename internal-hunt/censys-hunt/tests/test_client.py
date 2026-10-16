from datetime import datetime, timezone

import pytest
from censys_hunt.client import CensysClient
from conftest import CERT_SUBJECT, SEARCH_URL, censys_answer, censys_host
from connectors_sdk.connectors.internal_hunt import HuntExecutionError, RunDeadline

API_URL = "https://api.platform.censys.io"


@pytest.fixture
def deadline() -> RunDeadline:
    return RunDeadline(30)


def test_search_pages_and_maps_hosts_and_web_properties(requests_mock, deadline):
    # Given two pages of hits: a host, a web property, one named by its IP address and unusable hits
    web_property = {
        "web_property_v1": {
            "resource": {
                "hostname": "c2.evil.example",
                "port": 8443,
                "endpoints": [{"http": {"html_title": "Login"}}],
            }
        }
    }
    web_property_ip = {
        "web_property_v1": {"resource": {"hostname": "9.9.9.9", "port": 80}}
    }
    requests_mock.post(
        SEARCH_URL,
        [
            {
                "json": censys_answer(
                    [censys_host("8.8.8.8", ["evil.example"]), web_property],
                    "page-2",
                    total=5,
                )
            },
            {
                "json": censys_answer(
                    [web_property_ip, {"host_v1": {"resource": {}}}, {}], total=5
                )
            },
        ],
    )
    client = CensysClient(API_URL, "token", "org-1")

    # When searching
    result = client.search('host.services.jarm.fingerprint = "x"', 10, deadline)

    # Then both pages are read with the organization and the bearer token
    first, second = requests_mock.request_history
    assert first.headers["Authorization"] == "Bearer token"
    assert first.qs == {"organization_id": ["org-1"]}
    assert first.json() == {
        "query": 'host.services.jarm.fingerprint = "x"',
        "page_size": 10,
    }
    assert second.json()["page_token"] == "page-2"
    assert second.json()["page_size"] == 8
    assert (result.total, result.read, result.requests) == (5, 5, 2)
    host, web, web_ip = result.hosts
    assert host.key == "8.8.8.8" and host.asn == 20473 and host.as_name == "AS-CHOOPA"
    assert host.domains == ["evil.example"] and host.ports == [443]
    assert host.certificates[0].subject == CERT_SUBJECT
    assert set(host.fingerprints) == {
        "ja4x",
        "jarm",
        "ja4s",
        "banner_sha256",
        "http.title",
        "http.body_sha256",
    }
    assert host.last_seen == datetime(2026, 10, 3, 8, tzinfo=timezone.utc)
    assert web.key == "c2.evil.example" and web.ip is None and web.ports == [8443]
    assert web.fingerprints == {"http.title": ["Login"]}
    assert web_ip.ip == "9.9.9.9"


def test_search_stops_at_the_limit(requests_mock, deadline):
    # Given a page holding more hits than the limit
    requests_mock.post(
        SEARCH_URL,
        json=censys_answer(
            [censys_host("8.8.8.8"), censys_host("1.1.1.1")], "next", total=9
        ),
    )
    client = CensysClient(API_URL, "token", None)

    # When searching with a limit of one hit
    result = client.search("q", 1, deadline)

    # Then one page is read, without organization, and the result is truncated
    assert requests_mock.call_count == 1
    assert requests_mock.last_request.qs == {}
    assert [host.key for host in result.hosts] == ["8.8.8.8"]
    assert result.read == 1 and result.truncated is True


def test_unusable_hits_count_against_the_limit(requests_mock, deadline):
    # Given a first page holding a hit that maps to no host
    requests_mock.post(
        SEARCH_URL,
        [
            {"json": censys_answer([{}, censys_host("8.8.8.8")], "next", total=9)},
            {"json": censys_answer([censys_host("1.1.1.1")], "last", total=9)},
        ],
    )
    client = CensysClient(API_URL, "token", None)

    # When searching with a limit of two hits
    result = client.search("q", 2, deadline)

    # Then the unusable hit counts against the limit
    assert requests_mock.call_count == 1
    assert [host.key for host in result.hosts] == ["8.8.8.8"]
    assert result.read == 2


def test_unexpected_answers_fail(requests_mock, deadline):
    requests_mock.post(SEARCH_URL, json=[1])
    client = CensysClient(API_URL, "token", None)
    with pytest.raises(HuntExecutionError, match="unexpected answer"):
        client.search("q", 5, deadline)
