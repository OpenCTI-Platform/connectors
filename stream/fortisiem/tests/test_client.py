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
