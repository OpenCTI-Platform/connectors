from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import requests
from fortisiem_client import FortiSIEMClient
from fortisiem_client.api_client import extract_value


def _make_client() -> FortiSIEMClient:
    fortisiem = SimpleNamespace(
        api_base_url="https://fortisiem.example.com",
        organization="super",
        username="api-user",
        password=SimpleNamespace(get_secret_value=lambda: "pw"),
        watchlist_id=1,
        entry_age_out="30d",
        ssl_verify=True,
    )
    client = FortiSIEMClient(SimpleNamespace(fortisiem=fortisiem), MagicMock())
    client.session = MagicMock()
    return client


def _response(status: int = 200) -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.raise_for_status.return_value = None
    return response


@pytest.mark.parametrize(
    "pattern, expected",
    [
        ("[ipv4-addr:value = '198.51.100.1']", "198.51.100.1"),
        ("[ipv6-addr:value = '2001:db8::1']", "2001:db8::1"),
        ("[domain-name:value = 'evil.example.com']", "evil.example.com"),
        ("[url:value = 'http://evil.example.com/x']", "http://evil.example.com/x"),
        ("[file:hashes.'SHA-256' = 'abc']", "abc"),
        ("[email-addr:value = 'a@b.com']", None),
        ("garbage", None),
        ("", None),
    ],
)
def test_extract_value(pattern, expected):
    assert extract_value(pattern) == expected


def test_organization_prefix_in_auth():
    fortisiem = SimpleNamespace(
        api_base_url="https://fortisiem.example.com",
        organization="super",
        username="api-user",
        password=SimpleNamespace(get_secret_value=lambda: "pw"),
        watchlist_id=1,
        entry_age_out="30d",
        ssl_verify=True,
    )
    # Build with the real requests.Session created in __init__ (no session mock).
    client = FortiSIEMClient(SimpleNamespace(fortisiem=fortisiem), MagicMock())
    assert client.session.auth == ("super/api-user", "pw")


def test_add_indicator_posts_entry():
    client = _make_client()
    client.session.request.return_value = _response(200)

    assert (
        client.add_indicator({"pattern": "[ipv4-addr:value = '198.51.100.1']"}) is True
    )
    call = client.session.request.call_args
    assert call.args[0] == "post"
    assert call.args[1].endswith("/phoenix/rest/watchlist/addTo")
    body = call.kwargs["json"]
    assert body["parameters"]["watchlistId"] == 1
    assert body["json_body"][0]["entryValue"] == "198.51.100.1"
    assert body["json_body"][0]["ageOut"] == "30d"


def test_add_indicator_releases_successful_response():
    # The successful response body is not used, so the connection must be
    # released back to the session pool.
    client = _make_client()
    ok = _response(200)
    client.session.request.return_value = ok

    assert client.add_indicator({"pattern": "[ipv4-addr:value = '1.1.1.1']"}) is True
    ok.close.assert_called_once()


def test_add_indicator_skips_unsupported():
    client = _make_client()
    assert client.add_indicator({"pattern": "[email-addr:value = 'a@b.com']"}) is False
    client.session.request.assert_not_called()


def test_add_indicator_returns_false_on_error():
    client = _make_client()
    client.session.request.side_effect = requests.RequestException("boom")

    with patch("fortisiem_client.api_client.time.sleep"):
        assert (
            client.add_indicator({"pattern": "[ipv4-addr:value = '1.1.1.1']"}) is False
        )


def test_request_retries_on_rate_limit():
    client = _make_client()
    client.session.request.side_effect = [_response(429), _response(200)]

    with patch("fortisiem_client.api_client.time.sleep") as sleep:
        result = client._request("post", "/phoenix/rest/watchlist/addTo", json={})

    assert result is not None
    assert client.session.request.call_count == 2
    sleep.assert_called_once()


def test_request_fails_fast_on_4xx_without_retry():
    client = _make_client()
    forbidden = _response(403)
    forbidden.raise_for_status.side_effect = requests.HTTPError("403")
    client.session.request.return_value = forbidden

    with patch("fortisiem_client.api_client.time.sleep") as sleep:
        assert client._request("post", "/phoenix/rest/watchlist/addTo", json={}) is None

    # No retry on a non-retriable 4xx: a single call and no backoff sleep.
    assert client.session.request.call_count == 1
    sleep.assert_not_called()


def test_request_retries_on_server_error():
    client = _make_client()
    client.session.request.side_effect = [_response(503), _response(200)]

    with patch("fortisiem_client.api_client.time.sleep") as sleep:
        result = client._request("post", "/phoenix/rest/watchlist/addTo", json={})

    assert result is not None
    assert client.session.request.call_count == 2
    sleep.assert_called_once()


def test_request_retries_on_connection_error():
    # Transient connection/timeout errors are retried with backoff.
    client = _make_client()
    client.session.request.side_effect = [
        requests.ConnectionError("down"),
        _response(200),
    ]

    with patch("fortisiem_client.api_client.time.sleep") as sleep:
        result = client._request("post", "/phoenix/rest/watchlist/addTo", json={})

    assert result is not None
    assert client.session.request.call_count == 2
    sleep.assert_called_once()


def test_request_fails_fast_on_non_transient_request_error():
    # A non-transient requests error (e.g. invalid URL/schema) is not retried.
    client = _make_client()
    client.session.request.side_effect = requests.exceptions.InvalidURL("bad url")

    with patch("fortisiem_client.api_client.time.sleep") as sleep:
        assert client._request("post", "/phoenix/rest/watchlist/addTo", json={}) is None

    assert client.session.request.call_count == 1
    sleep.assert_not_called()


def test_request_returns_none_when_connection_error_persists():
    # A connection error on every attempt is retried then gives up.
    client = _make_client()
    client.session.request.side_effect = requests.ConnectionError("down")

    with patch("fortisiem_client.api_client.time.sleep"):
        assert client._request("post", "/phoenix/rest/watchlist/addTo", json={}) is None

    assert client.session.request.call_count == FortiSIEMClient.REQUEST_ATTEMPTS


def test_request_returns_none_when_rate_limited_on_every_attempt():
    # 429 on every attempt is retried then gives up after REQUEST_ATTEMPTS.
    client = _make_client()
    client.session.request.return_value = _response(429)

    with patch("fortisiem_client.api_client.time.sleep"):
        assert client._request("post", "/phoenix/rest/watchlist/addTo", json={}) is None

    assert client.session.request.call_count == FortiSIEMClient.REQUEST_ATTEMPTS


def test_request_closes_response_on_4xx():
    # A non-retriable 4xx response must be released back to the connection pool.
    client = _make_client()
    forbidden = _response(403)
    forbidden.raise_for_status.side_effect = requests.HTTPError("403")
    client.session.request.return_value = forbidden

    with patch("fortisiem_client.api_client.time.sleep"):
        assert client._request("post", "/phoenix/rest/watchlist/addTo", json={}) is None

    forbidden.close.assert_called_once()


def test_request_closes_superseded_response_before_retry():
    # The 429 response that is not returned is closed; the returned 200 is not.
    client = _make_client()
    rate_limited = _response(429)
    ok = _response(200)
    client.session.request.side_effect = [rate_limited, ok]

    with patch("fortisiem_client.api_client.time.sleep"):
        result = client._request("post", "/phoenix/rest/watchlist/addTo", json={})

    assert result is ok
    rate_limited.close.assert_called_once()
    ok.close.assert_not_called()
