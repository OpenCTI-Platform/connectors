from unittest.mock import MagicMock

import pytest
import requests
from conftest import RFC_QUERY, FakeResponse, FakeSession, default_routes, load_fixture
from dnslytics_client import DnslyticsApiError, DnslyticsClient, api_client


def make_client(routes=None) -> DnslyticsClient:
    return DnslyticsClient(
        MagicMock(),
        api_base_url="https://api.dnslytics.net/",
        api_key="secret-key",
        session=FakeSession(routes or default_routes()),
        sleep=lambda _: None,
    )


def test_search_domains_parses_hits_and_total():
    client = make_client()

    result = client.search_domains(RFC_QUERY)

    assert result.ndomains == 5
    assert [(hit.domain, hit.active) for hit in result.domains][:2] == [
        ("armeniadaily.am", True),
        ("armenianews.example", True),
    ]
    url, params = client.session.calls[0]
    assert url == "https://api.dnslytics.net/v2/dataset/domains"
    assert params == {"q": RFC_QUERY, "page": 1, "apikey": "secret-key"}


def test_error_body_is_raised_with_its_reason():
    client = make_client(
        {"/v2/dataset/domains": FakeResponse(403, load_fixture("error_forbidden.json"))}
    )

    with pytest.raises(DnslyticsApiError) as err:
        client.search_domains(RFC_QUERY)

    assert err.value.reason == "Forbidden access denied!"
    assert err.value.status_code == 403
    assert len(client.session.calls) == 1


def test_error_body_with_http_200_is_still_an_error():
    client = make_client(
        {"/v2/dataset/domains": {"status": "error", "data": "Invalid query"}}
    )

    with pytest.raises(DnslyticsApiError, match="Invalid query"):
        client.search_domains("name:")


@pytest.mark.parametrize("status", [429, 503])
def test_throttling_and_unavailable_are_retried(status):
    error = FakeResponse(status, {"status": "error", "data": "Service Unavailable"})
    ok = load_fixture("dataset_domains_rfc_query.json")
    client = make_client({"/v2/dataset/domains": [error, ok]})

    assert client.search_domains(RFC_QUERY).ndomains == 5
    assert len(client.session.calls) == 2


def test_retries_are_bounded():
    error = FakeResponse(503, {"status": "error", "data": "Service Unavailable"})
    client = make_client({"/v2/dataset/domains": [error]})

    with pytest.raises(DnslyticsApiError, match="Service Unavailable"):
        client.search_domains(RFC_QUERY)

    assert len(client.session.calls) == len(api_client.RETRY_DELAYS_SECONDS) + 1


def test_network_error_does_not_leak_api_key():
    client = make_client(
        {
            "/v2/dataset/domains": requests.ConnectionError(
                "HTTPSConnectionPool: /v2/dataset/domains?q=x&apikey=secret-key"
            )
        }
    )

    with pytest.raises(DnslyticsApiError) as err:
        client.search_domains("x")

    assert "secret-key" not in str(err.value)


def test_ip2asn_returns_number_and_name():
    client = make_client()

    as_info = client.ip2asn("45.84.204.99")

    assert (as_info.number, as_info.name) == (47583, "Hostinger International Limited")
    url, params = client.session.calls[0]
    assert url == "https://freeapi.dnslytics.net/v1/ip2asn/45.84.204.99"
    # The free endpoint never gets the API key
    assert params is None


def test_ip2asn_not_announced_returns_none():
    client = make_client(
        {"/v1/ip2asn/192.168.1.1": load_fixture("ip2asn_not_announced.json")}
    )

    assert client.ip2asn("192.168.1.1") is None


def test_ip2asn_daily_cap_is_enforced_client_side(monkeypatch):
    monkeypatch.setattr(api_client, "IP2ASN_DAILY_CAP", 2)
    client = make_client()

    client.ip2asn("45.84.204.99")
    client.ip2asn("45.84.204.99")
    with pytest.raises(DnslyticsApiError, match="daily cap"):
        client.ip2asn("45.84.204.99")

    assert len(client.session.calls) == 2


def test_account_info_is_read_from_the_free_endpoint():
    client = make_client()

    assert client.account_info()["apicredits"] == 145638
    assert client.session.calls[0][0] == "https://api.dnslytics.net/v1/accountinfo"


def test_rate_limiter_waits_when_the_window_is_full(monkeypatch):
    now = [0.0]
    slept = []
    monkeypatch.setattr(
        api_client.time,
        "sleep",
        lambda s: (slept.append(s), now.__setitem__(0, now[0] + s)),
    )
    limiter = api_client.RateLimiter(max_calls=2, period=60, clock=lambda: now[0])

    limiter.wait()
    limiter.wait()
    now[0] = 10.0
    limiter.wait()

    assert slept == [50.0]
