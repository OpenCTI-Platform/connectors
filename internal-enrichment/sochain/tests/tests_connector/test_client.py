"""Unit tests for SochainClient (HTTP layer mocked)."""

from unittest.mock import MagicMock

import pytest
from sochain_client import SochainAPIError, SochainClient

ADDRESS = "bc1qxhmdufsvnuaaaer4ynz88fspdsxq2h9e9cetdj"


class FakeResp:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


def _client(response, api_key=None):
    client = SochainClient(
        helper=MagicMock(), base_url="https://sochain.com/api/v3/", api_key=api_key
    )
    session = MagicMock()
    session.get.return_value = response
    client.session = session
    return client, session


def test_address_summary_returns_data_and_calls_the_right_path():
    client, session = _client(
        FakeResp(200, {"status": "success", "data": {"txs_total": 3}})
    )

    assert client.address_summary("BTC", ADDRESS) == {"txs_total": 3}
    assert (
        session.get.call_args.args[0]
        == f"https://sochain.com/api/v3/address_summary/BTC/{ADDRESS}"
    )


def test_address_poisoning_calls_the_right_path():
    client, session = _client(
        FakeResp(200, {"status": "success", "data": {"findings": []}})
    )

    assert client.address_poisoning("DOGE", "DAddr") == {"findings": []}
    assert (
        session.get.call_args.args[0]
        == "https://sochain.com/api/v3/address_poisoning/DOGE/DAddr"
    )


def test_no_key_sends_no_auth_header():
    client, session = _client(FakeResp(200, {"status": "success", "data": {}}))
    client.address_summary("BTC", ADDRESS)

    assert session.get.call_args.kwargs["headers"] == {}


def test_key_is_sent_as_api_key_header_per_request():
    client, session = _client(
        FakeResp(200, {"status": "success", "data": {}}), api_key="k"
    )
    assert "API-KEY" not in client.session.headers
    client.address_summary("BTC", ADDRESS)

    assert session.get.call_args.kwargs["headers"] == {"API-KEY": "k"}


def test_404_raises_with_the_api_message():
    client, _ = _client(
        FakeResp(
            404,
            {
                "status": "fail",
                "data": {
                    "error_message": "Unable to fetch address summary. Invalid address?"
                },
            },
        )
    )
    with pytest.raises(SochainAPIError) as exc:
        client.address_summary("BTC", "1bad")
    assert exc.value.status_code == 404
    assert "Invalid address?" in str(exc.value)


def test_401_raises():
    client, _ = _client(
        FakeResp(401, {"status": "fail", "data": {"error_message": "API Key invalid"}})
    )
    with pytest.raises(SochainAPIError) as exc:
        client.address_summary("BTC", ADDRESS)
    assert exc.value.status_code == 401


def test_429_raises_and_points_to_a_key():
    client, _ = _client(FakeResp(429, text="slow down"))
    with pytest.raises(SochainAPIError) as exc:
        client.address_summary("BTC", ADDRESS)
    assert exc.value.status_code == 429
    assert "sochain.com/dashboard" in str(exc.value)


def test_fail_status_on_200_raises():
    client, _ = _client(FakeResp(200, {"status": "fail", "data": {}}))
    with pytest.raises(SochainAPIError):
        client.address_summary("BTC", ADDRESS)


def test_non_json_200_raises():
    client, _ = _client(FakeResp(200, text="<html>blocked</html>"))
    with pytest.raises(SochainAPIError):
        client.address_summary("BTC", ADDRESS)


def test_redirects_are_not_followed():
    client, session = _client(FakeResp(302, None))

    with pytest.raises(SochainAPIError, match="redirect"):
        client.address_summary("BTC", ADDRESS)
    assert session.get.call_args.kwargs["allow_redirects"] is False
