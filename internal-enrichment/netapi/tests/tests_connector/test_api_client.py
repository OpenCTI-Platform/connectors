"""Tests for the NetAPI JSON API client: requests, token and errors."""

from unittest.mock import MagicMock

import pytest
import requests
from connectors_sdk.exceptions.error import DataRetrievalError
from mock_responses import CHECK_LISTED_NOW, ERROR_INVALID_VALUE, RANK_IN_TOP_1M
from netapi_client import NetAPIClient, NetAPIError


class FakeResponse:
    def __init__(self, status_code=200, body=None, headers=None, reason="OK"):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}
        self.reason = reason

    def json(self):
        if self._body is None:
            raise ValueError("no JSON")
        return self._body


def make_client(response, api_token=None):
    client = NetAPIClient(api_token=api_token, timeout=7)
    client._session.get = MagicMock(return_value=response)
    return client


def test_compromised_check_sends_one_get_with_the_method_and_value():
    client = make_client(FakeResponse(body=CHECK_LISTED_NOW))

    answer = client.compromised_check("000359.xyz")

    assert answer == CHECK_LISTED_NOW
    client._session.get.assert_called_once_with(
        "https://netapi.com/api-json/",
        params={
            "method": "compromised-check",
            "source": "opencti",
            "value": "000359.xyz",
        },
        timeout=7,
    )


def test_domain_rank_sends_the_domain_parameter():
    client = make_client(FakeResponse(body=RANK_IN_TOP_1M))

    assert client.domain_rank("github.com") == RANK_IN_TOP_1M
    params = client._session.get.call_args.kwargs["params"]
    assert params == {
        "method": "domain-rank",
        "source": "opencti",
        "domain": "github.com",
    }


def test_token_goes_into_the_authorization_header_only():
    client = make_client(FakeResponse(body=CHECK_LISTED_NOW), api_token="abc123")

    client.compromised_check("000359.xyz")

    assert client._session.headers["Authorization"] == "Bearer abc123"
    assert "token" not in client._session.get.call_args.kwargs["params"]


def test_without_a_token_no_authorization_header_is_sent():
    client = make_client(FakeResponse(body=CHECK_LISTED_NOW))
    assert "Authorization" not in client._session.headers


def test_api_error_is_raised_with_its_code_and_message():
    client = make_client(FakeResponse(status_code=400, body=ERROR_INVALID_VALUE))

    with pytest.raises(NetAPIError) as err:
        client.compromised_check("not a host")

    assert err.value.status_code == 400
    assert err.value.code == "invalid_value"
    assert "value must be a domain name" in str(err.value)
    assert isinstance(err.value, DataRetrievalError)


def test_rate_limit_reports_the_retry_delay():
    client = make_client(
        FakeResponse(
            status_code=429,
            body={"error": {"code": "rate_limited", "message": "Too many requests"}},
            headers={"Retry-After": "42"},
        )
    )

    with pytest.raises(NetAPIError) as err:
        client.compromised_check("000359.xyz")

    assert err.value.code == "rate_limited"
    assert "retry after 42 s" in str(err.value)


def test_non_json_answer_is_an_error():
    client = make_client(FakeResponse(status_code=200, body=None))

    with pytest.raises(NetAPIError) as err:
        client.compromised_check("000359.xyz")

    assert err.value.code == "not_json"


def test_error_with_a_non_json_body_keeps_the_status():
    client = make_client(FakeResponse(status_code=502, body=None, reason="Bad Gateway"))

    with pytest.raises(NetAPIError) as err:
        client.compromised_check("000359.xyz")

    assert err.value.status_code == 502


def test_network_failure_is_a_data_retrieval_error():
    client = NetAPIClient()
    client._session.get = MagicMock(
        side_effect=requests.ConnectionError("connection refused")
    )

    with pytest.raises(DataRetrievalError) as err:
        client.compromised_check("000359.xyz")

    assert "Could not reach the NetAPI API" in str(err.value)
