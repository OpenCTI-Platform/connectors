"""Tests for the IPGeolocation.io API client."""

from unittest.mock import MagicMock

import pytest
import requests
from connectors_sdk.exceptions.error import DataRetrievalError
from ipgeolocation_client import IPGeolocationAPIError, IPGeolocationClient
from mock_responses import MOCK_IPGEO_CLEAN, MOCK_IPGEO_FULL

FREE_PLAN_INCLUDE = {
    "message": "This feature is not supported on your subscription. This feature is available on Paid subscriptions only."
}
BASE_ONLY = {
    k: v for k, v in MOCK_IPGEO_CLEAN.items() if k not in ("security", "abuse")
}


def _response(status_code=200, payload=None, reason="OK"):
    response = MagicMock()
    response.status_code = status_code
    response.reason = reason
    response.json.return_value = payload if payload is not None else {}
    return response


def _client(*responses, **kwargs):
    client = IPGeolocationClient(api_key="secret-key", **kwargs)
    client._session.get = MagicMock(side_effect=list(responses))
    return client


def test_lookup_requests_the_enabled_modules_in_one_call():
    client = _client(_response(payload=MOCK_IPGEO_FULL))

    intel = client.lookup("2.56.188.34")

    client._session.get.assert_called_once()
    url = client._session.get.call_args.args[0]
    params = client._session.get.call_args.kwargs["params"]
    assert url == "https://api.ipgeolocation.io/v3/ipgeo"
    assert params == {
        "apiKey": "secret-key",
        "ip": "2.56.188.34",
        "include": "security,abuse,hostname",
    }
    assert intel.ip == "2.56.188.34"
    assert intel.has_security is True
    assert intel.security.is_vpn is True


def test_lookup_without_modules_sends_no_include():
    client = _client(_response(payload=BASE_ONLY), include=())

    intel = client.lookup("8.8.8.8")

    assert "include" not in client._session.get.call_args.kwargs["params"]
    assert intel.has_security is False


def test_free_plan_falls_back_to_the_base_lookup_and_remembers_it():
    client = _client(
        _response(401, FREE_PLAN_INCLUDE),
        _response(payload=BASE_ONLY),
        _response(payload=BASE_ONLY),
    )

    intel = client.lookup("8.8.8.8")
    assert intel.location.country_name == "United States"
    assert intel.has_security is False
    calls = client._session.get.call_args_list
    assert [c.kwargs["params"].get("include") for c in calls] == [
        "security,abuse,hostname",
        None,
    ]

    client.lookup("8.8.4.4")  # the plan is remembered: one request, no include
    assert len(client._session.get.call_args_list) == 3
    assert "include" not in client._session.get.call_args.kwargs["params"]


def test_invalid_key_raises_with_the_api_message():
    invalid = {"message": "Provided API key is not valid."}
    client = _client(_response(401, invalid), _response(401, invalid))

    with pytest.raises(IPGeolocationAPIError) as err:
        client.lookup("8.8.8.8")

    assert err.value.status_code == 401
    assert "Provided API key is not valid." in str(err.value)
    assert isinstance(err.value, DataRetrievalError)


@pytest.mark.parametrize(
    "status_code, message",
    [
        (423, "'10.0.0.1' is a bogon IP address."),
        (429, "You have exceeded the limit of requests."),
        (404, "Provided IPv4 or IPv6 address does not exist in our database."),
    ],
)
def test_api_errors_raise(status_code, message):
    client = _client(_response(status_code, {"message": message}))

    with pytest.raises(IPGeolocationAPIError, match=message):
        client.lookup("10.0.0.1")


def test_connection_errors_never_show_the_api_key():
    client = IPGeolocationClient(api_key="secret-key")
    client._session.get = MagicMock(
        side_effect=requests.ConnectionError(
            "Max retries exceeded with url: /v3/ipgeo?apiKey=secret-key&ip=8.8.8.8"
        )
    )

    with pytest.raises(DataRetrievalError) as err:
        client.lookup("8.8.8.8")

    assert "secret-key" not in str(err.value)
    assert "apiKey=***" in str(err.value)


def test_quota_errors_are_not_retried():
    """429 means the plan's quota is used up: retrying would only waste time."""
    client = IPGeolocationClient(api_key="k")
    retry = client._session.get_adapter("https://api.ipgeolocation.io").max_retries

    assert 429 not in retry.status_forcelist
    assert set(retry.status_forcelist) == {502, 503, 504}
