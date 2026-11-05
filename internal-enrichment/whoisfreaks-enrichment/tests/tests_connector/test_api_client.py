"""Tests for the WhoisFreaks API client."""

import traceback
from unittest.mock import MagicMock

import pytest
import requests
from connectors_sdk.exceptions.error import DataRetrievalError
from mock_responses import MOCK_WHOIS_FULL
from whoisfreaks_client import WhoisFreaksAPIError, WhoisFreaksClient


def _response(status_code=200, payload=None, reason="OK"):
    response = MagicMock()
    response.status_code = status_code
    response.reason = reason
    response.json.return_value = payload if payload is not None else {}
    return response


def _client(*responses, **kwargs):
    client = WhoisFreaksClient(api_key="secret-key", **kwargs)
    client._session.get = MagicMock(side_effect=list(responses))
    return client


def test_lookup_builds_the_live_whois_request():
    client = _client(_response(payload=MOCK_WHOIS_FULL))

    record = client.lookup("example.com")

    client._session.get.assert_called_once()
    url = client._session.get.call_args.args[0]
    params = client._session.get.call_args.kwargs["params"]
    assert url == "https://api.whoisfreaks.com/v2.0/whois/live"
    assert params == {
        "apiKey": "secret-key",
        "whois": "live",
        "domainName": "example.com",
        "format": "json",
    }
    assert record.domain_name == "example.com"
    assert record.registrar.name.startswith("RESERVED")
    assert record.name_servers == ["A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"]


def test_application_level_failure_raises():
    client = _client(_response(payload={"status": False, "error": "Invalid domain"}))

    with pytest.raises(WhoisFreaksAPIError, match="Invalid domain"):
        client.lookup("not a domain")


def test_invalid_key_raises_with_the_api_message():
    invalid = {"error": "Invalid API key"}
    client = _client(_response(401, invalid))

    with pytest.raises(WhoisFreaksAPIError) as err:
        client.lookup("example.com")

    assert err.value.status_code == 401
    assert "Invalid API key" in str(err.value)
    assert isinstance(err.value, DataRetrievalError)


@pytest.mark.parametrize(
    "status_code, message",
    [
        (403, "You are not subscribed to any plan."),
        (429, "You have exceeded the limit of requests."),
    ],
)
def test_api_errors_raise(status_code, message):
    client = _client(_response(status_code, {"error": message}))

    with pytest.raises(WhoisFreaksAPIError, match=message):
        client.lookup("example.com")


def test_connection_errors_never_show_the_api_key():
    client = WhoisFreaksClient(api_key="secret-key")
    client._session.get = MagicMock(
        side_effect=requests.ConnectionError(
            "Max retries exceeded with url: "
            "/v2.0/whois/live?apiKey=secret-key&domainName=example.com"
        )
    )

    with pytest.raises(DataRetrievalError) as err:
        client.lookup("example.com")

    assert "secret-key" not in str(err.value)
    assert "apiKey=***" in str(err.value)


def test_quota_errors_are_not_retried():
    """429 means the plan's quota is used up: retrying would only waste time."""
    client = WhoisFreaksClient(api_key="k")
    retry = client._session.get_adapter("https://api.whoisfreaks.com").max_retries

    assert 429 not in retry.status_forcelist
    assert set(retry.status_forcelist) == {502, 503, 504}
    # A 429 Retry-After header must not make the client sleep past the timeout.
    assert retry.respect_retry_after_header is False


def test_api_key_is_absent_from_the_formatted_traceback():
    """The leaking cause is dropped (`from None`), so no traceback frame has the key."""
    client = WhoisFreaksClient(api_key="secret-key")
    client._session.get = MagicMock(
        side_effect=requests.ConnectionError(
            "Max retries exceeded with url: "
            "/v2.0/whois/live?apiKey=secret-key&domainName=example.com"
        )
    )

    with pytest.raises(DataRetrievalError) as err:
        client.lookup("example.com")

    tb = "".join(
        traceback.format_exception(type(err.value), err.value, err.value.__traceback__)
    )
    assert "secret-key" not in tb
    assert "apiKey=***" in tb
