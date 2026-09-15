"""Unit tests for MacadressClient (HTTP layer mocked)."""

from unittest.mock import MagicMock

import pytest
from macadress_client import MacadressAPIError, MacadressClient


class FakeResp:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


def _client(response):
    client = MacadressClient(helper=MagicMock(), base_url="http://x", api_key="mk_k")
    session = MagicMock()
    session.get.return_value = response
    client.session = session
    return client


def test_lookup_ok_returns_payload():
    client = _client(FakeResp(200, {"valid": True, "organization": "Apple, Inc."}))
    assert client.lookup("F0:18:98:11:22:33")["organization"] == "Apple, Inc."


def test_bearer_header_sent_per_request_not_on_session():
    client = MacadressClient(helper=MagicMock(), base_url="http://x", api_key="mk_k")
    assert client._auth_header == {"Authorization": "Bearer mk_k"}
    assert "Authorization" not in client.session.headers

    session = MagicMock()
    session.get.return_value = FakeResp(200, {"valid": True})
    client.session = session
    client.lookup("F0:18:98:11:22:33")
    assert session.get.call_args.kwargs["headers"] == {"Authorization": "Bearer mk_k"}


def test_400_raises_invalid_mac():
    with pytest.raises(MacadressAPIError) as exc:
        _client(FakeResp(400, {"error": "parse"})).lookup("nope")
    assert exc.value.status_code == 400
    assert "not a valid MAC" in str(exc.value)


def test_401_raises_with_status():
    with pytest.raises(MacadressAPIError) as exc:
        _client(FakeResp(401, text="unauthorized")).lookup("00:11:22:33:44:55")
    assert exc.value.status_code == 401


def test_429_raises():
    with pytest.raises(MacadressAPIError):
        _client(FakeResp(429, text="slow down")).lookup("00:11:22:33:44:55")


def test_500_raises():
    with pytest.raises(MacadressAPIError):
        _client(FakeResp(503, text="boom")).lookup("00:11:22:33:44:55")


def test_non_json_200_raises():
    # A 200 with an HTML/WAF body must fail loudly, not return an unparsable value.
    with pytest.raises(MacadressAPIError):
        _client(FakeResp(200, text="<html>blocked</html>")).lookup("00:11:22:33:44:55")
