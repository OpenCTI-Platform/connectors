"""Tests for zetalytics_dns.client."""

from unittest.mock import MagicMock, patch

import pytest
from zetalytics_dns.client import ZetalyticsClient


@pytest.fixture
def mock_zetalytics(monkeypatch):
    """Patch the zetalytics.Zetalytics class to avoid real API calls."""
    mock = MagicMock()
    monkeypatch.setattr("zetalytics_dns.client.Zetalytics", mock)
    return mock


@pytest.fixture
def client(mock_zetalytics) -> ZetalyticsClient:
    return ZetalyticsClient(token="test-token")


def test_client_initialises_with_token(mock_zetalytics, client):
    mock_zetalytics.assert_called_once_with(token="test-token")


def test_passive_dns_for_domain_calls_correct_method(client):
    client._client.domain2rrtypes.return_value = {"results": []}

    result = client.passive_dns_for_domain(
        value="example.com",
        size=100,
        lookback_days=90,
        tsfield="all",
    )

    client._client.domain2rrtypes.assert_called_once()
    call_kwargs = client._client.domain2rrtypes.call_args.kwargs
    assert call_kwargs["q"] == "example.com"
    assert call_kwargs["size"] == 100
    assert call_kwargs["tsfield"] == "all"
    assert "rrtypes" in call_kwargs
    assert result == {"results": []}


def test_passive_dns_for_domain_includes_start_date(client):
    client._client.domain2rrtypes.return_value = {"results": []}
    client.passive_dns_for_domain(
        value="example.com", size=50, lookback_days=365, tsfield="last_seen"
    )
    call_kwargs = client._client.domain2rrtypes.call_args.kwargs
    assert "start" in call_kwargs
    # Start date should be a valid ISO date string
    start = call_kwargs["start"]
    assert len(start) == 10  # YYYY-MM-DD


def test_passive_dns_for_ip_calls_ip_endpoint(client):
    client._client.ip.return_value = {"results": []}

    result = client.passive_dns_for_ip(
        value="1.2.3.4", size=50, lookback_days=30, tsfield="all"
    )

    client._client.ip.assert_called_once()
    call_kwargs = client._client.ip.call_args.kwargs
    assert call_kwargs["q"] == "1.2.3.4"
    assert call_kwargs["size"] == 50
    assert result == {"results": []}


def test_live_dns_calls_correct_method(client):
    client._client.liveDNS.return_value = {"results": []}

    result = client.live_dns("example.com")

    client._client.liveDNS.assert_called_once_with(q="example.com")
    assert result == {"results": []}


def test_subdomains_passes_parameters(client):
    client._client.subdomains.return_value = {"results": []}

    client.subdomains(value="example.com", max_results=200)

    call_kwargs = client._client.subdomains.call_args.kwargs
    assert call_kwargs["q"] == "example.com"
    assert "size" not in call_kwargs  # SDK does not support size for subdomains
    assert call_kwargs["vvv"] is True
    assert call_kwargs["sort"] == "last"


def test_ip_context_calls_ip2pwhois(client):
    client._client.ip2pwhois.return_value = {"results": []}

    result = client.ip_context("1.2.3.4")

    client._client.ip2pwhois.assert_called_once_with(q="1.2.3.4")
    assert result == {"results": []}


def test_domain_d8s_calls_correct_method(client):
    client._client.domain2d8s.return_value = {"results": []}

    result = client.domain_d8s("example.com")

    client._client.domain2d8s.assert_called_once_with(q="example.com")
    assert result == {"results": []}


def test_domain_ns_glue_calls_correct_method(client):
    client._client.domain2nsglue.return_value = {"results": []}

    result = client.domain_ns_glue("example.com")

    client._client.domain2nsglue.assert_called_once_with(q="example.com")
    assert result == {"results": []}


def test_ip_ns_glue_calls_correct_method(client):
    client._client.ip2nsglue.return_value = {"results": []}

    result = client.ip_ns_glue("1.2.3.4")

    client._client.ip2nsglue.assert_called_once_with(q="1.2.3.4")
    assert result == {"results": []}


def test_lookback_start_returns_past_date(client):
    import datetime

    start_str = client._lookback_start(90)
    start_date = datetime.date.fromisoformat(start_str)
    expected = datetime.date.today() - datetime.timedelta(days=90)
    assert start_date == expected
