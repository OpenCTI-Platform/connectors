from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import requests
from fortiedr_client import FortiEDRClient
from fortiedr_client.api_client import extract_ip


def _make_client() -> FortiEDRClient:
    fortiedr = SimpleNamespace(
        api_base_url="https://console.fortiedr.example.com",
        organization="",
        username="api-user",
        password=SimpleNamespace(get_secret_value=lambda: "pw"),
        ip_set_name="OpenCTI",
        ssl_verify=True,
    )
    client = FortiEDRClient(SimpleNamespace(fortiedr=fortiedr), MagicMock())
    client.session = MagicMock()
    return client


def _response(status: int = 200, payload=None) -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.json.return_value = payload if payload is not None else {}
    response.raise_for_status.return_value = None
    return response


@pytest.mark.parametrize(
    "pattern, expected",
    [
        ("[ipv4-addr:value = '198.51.100.1']", "198.51.100.1"),
        ("[ipv6-addr:value = '2001:db8::1']", "2001:db8::1"),
        ('[ipv4-addr:value = "198.51.100.1"]', "198.51.100.1"),
        ('[ipv6-addr:value = "2001:db8::1"]', "2001:db8::1"),
        ("[domain-name:value = 'evil.example.com']", None),
        ("[file:hashes.SHA-256 = 'aa']", None),
        ("garbage", None),
    ],
)
def test_extract_ip(pattern, expected):
    assert extract_ip(pattern) == expected


def test_organization_prefix_in_auth():
    fortiedr = SimpleNamespace(
        api_base_url="https://console.fortiedr.example.com",
        organization="ACME",
        username="api-user",
        password=SimpleNamespace(get_secret_value=lambda: "pw"),
        ip_set_name="OpenCTI",
        ssl_verify=True,
    )
    client = FortiEDRClient(SimpleNamespace(fortiedr=fortiedr), MagicMock())
    assert client.session.auth == ("ACME\\api-user", "pw")


def test_add_indicator_skips_unsupported():
    client = _make_client()
    assert client.add_indicator({"pattern": "[domain-name:value = 'x.com']"}) is False
    client.session.request.assert_not_called()


def test_add_indicator_creates_set_when_missing():
    client = _make_client()
    # list-ip-sets returns no matching set -> create
    client.session.request.side_effect = [
        _response(200, {"ipSets": []}),
        _response(200, {}),
    ]

    assert (
        client.add_indicator({"pattern": "[ipv4-addr:value = '198.51.100.1']"}) is True
    )
    create_call = client.session.request.call_args_list[1]
    assert create_call.args[0] == "post"
    assert create_call.args[1].endswith("/create-ip-set")
    assert create_call.kwargs["json"]["include"] == ["198.51.100.1"]


def test_add_indicator_updates_existing_set():
    client = _make_client()
    client.session.request.side_effect = [
        _response(200, {"ipSets": [{"name": "OpenCTI", "include": ["203.0.113.9"]}]}),
        _response(200, {}),
    ]

    assert (
        client.add_indicator({"pattern": "[ipv4-addr:value = '198.51.100.1']"}) is True
    )
    update_call = client.session.request.call_args_list[1]
    assert update_call.args[0] == "put"
    assert update_call.args[1].endswith("/update-ip-set")
    assert set(update_call.kwargs["json"]["include"]) == {"203.0.113.9", "198.51.100.1"}


def test_add_indicator_noop_when_already_present():
    client = _make_client()
    client.session.request.return_value = _response(
        200, {"ipSets": [{"name": "OpenCTI", "include": ["198.51.100.1"]}]}
    )

    assert (
        client.add_indicator({"pattern": "[ipv4-addr:value = '198.51.100.1']"}) is True
    )
    # Only the list call happened, no save
    assert client.session.request.call_count == 1


def test_remove_indicator_updates_set():
    client = _make_client()
    client.session.request.side_effect = [
        _response(
            200,
            {
                "ipSets": [
                    {"name": "OpenCTI", "include": ["198.51.100.1", "203.0.113.9"]}
                ]
            },
        ),
        _response(200, {}),
    ]

    assert (
        client.remove_indicator({"pattern": "[ipv4-addr:value = '198.51.100.1']"})
        is True
    )
    update_call = client.session.request.call_args_list[1]
    assert update_call.kwargs["json"]["include"] == ["203.0.113.9"]


def test_remove_indicator_noop_when_absent():
    client = _make_client()
    client.session.request.return_value = _response(
        200, {"ipSets": [{"name": "OpenCTI", "include": ["203.0.113.9"]}]}
    )

    assert (
        client.remove_indicator({"pattern": "[ipv4-addr:value = '198.51.100.1']"})
        is True
    )
    assert client.session.request.call_count == 1


def test_membership_update_fails_when_list_request_fails():
    # When list-ip-sets fails (e.g. FortiEDR outage), the client must not
    # guess membership: no create/update call, and False is returned so the
    # connector does not log a false success.
    client = _make_client()
    client.session.request.side_effect = requests.RequestException("boom")

    with patch("fortiedr_client.api_client.time.sleep"):
        assert (
            client.add_indicator({"pattern": "[ipv4-addr:value = '198.51.100.1']"})
            is False
        )
        client.session.request.side_effect = requests.RequestException("boom")
        assert (
            client.remove_indicator({"pattern": "[ipv4-addr:value = '198.51.100.1']"})
            is False
        )


def test_request_retries_on_rate_limit():
    client = _make_client()
    client.session.request.side_effect = [_response(429), _response(200)]

    with patch("fortiedr_client.api_client.time.sleep") as sleep:
        result = client._request("get", "/management-rest/ip-sets/list-ip-sets")

    assert result is not None
    assert client.session.request.call_count == 2
    sleep.assert_called_once()


def test_request_returns_none_on_error():
    client = _make_client()
    client.session.request.side_effect = requests.RequestException("boom")

    with patch("fortiedr_client.api_client.time.sleep"):
        assert client._request("get", "/x") is None


def test_request_fails_fast_on_4xx_without_retry():
    client = _make_client()
    forbidden = _response(403)
    forbidden.raise_for_status.side_effect = requests.HTTPError("403")
    client.session.request.return_value = forbidden

    with patch("fortiedr_client.api_client.time.sleep") as sleep:
        assert client._request("get", "/x") is None

    # No retry on a non-retriable 4xx: a single call and no backoff sleep.
    assert client.session.request.call_count == 1
    sleep.assert_not_called()


def test_request_retries_on_server_error():
    client = _make_client()
    client.session.request.side_effect = [_response(503), _response(200)]

    with patch("fortiedr_client.api_client.time.sleep") as sleep:
        assert client._request("get", "/x") is not None

    assert client.session.request.call_count == 2
    sleep.assert_called_once()
