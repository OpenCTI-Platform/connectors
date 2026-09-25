"""Unit tests for the shared MetrasClient (HTTP layer mocked)."""

from unittest.mock import MagicMock

import pytest
from metras_client import MetrasAPIError, MetrasClient


class FakeResp:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text
        self.content = b"x" if (payload is not None or text) else b""

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


def _client(responses):
    client = MetrasClient(helper=MagicMock(), base_url="http://x/api", api_key="k")
    session = MagicMock()
    session.request.side_effect = list(responses)
    client.session = session
    return client


def test_ping_ok():
    assert _client([FakeResp(200, {"endpoints": []})]).ping() is True


def test_auth_error_raises_with_status():
    client = _client([FakeResp(401, text="nope")])
    with pytest.raises(MetrasAPIError) as exc:
        client.ping()
    assert exc.value.status_code == 401


def test_server_error_raises():
    with pytest.raises(MetrasAPIError):
        _client([FakeResp(500, text="boom")])._get("/v1/endpoints")


def test_non_json_response_raises():
    # A 200 with a non-JSON body (WAF/HTML/proxy error page) must fail loudly,
    # not silently return an unparsable payload that looks like an empty result.
    with pytest.raises(MetrasAPIError):
        _client([FakeResp(200, text="<html>blocked</html>")])._get("/v1/endpoints")


def test_iter_edr_alerts_paginates_until_more_false():
    client = _client(
        [
            FakeResp(200, {"data": [{"id": "1"}, {"id": "2"}], "more": True}),
            FakeResp(200, {"data": [{"id": "3"}], "more": False}),
        ]
    )
    assert [a["id"] for a in client.iter_edr_alerts(page_size=2)] == ["1", "2", "3"]


def test_iter_binaries_stops_on_short_page():
    client = _client([FakeResp(200, {"data": [{"md5": "a"}]})])
    assert len(list(client.iter_binaries(page_size=50))) == 1


def test_create_blocklist_handles_empty_202():
    assert _client([FakeResp(202)]).create_blocklist([{"name": "x"}]) == {}


def test_list_blocklists_filters_by_name():
    client = _client([FakeResp(200, {"data": [{"id": "b1", "name": "n"}]})])
    assert client.list_blocklists(name="n")["data"][0]["id"] == "b1"


def test_binary_by_hash_uses_query():
    client = _client([FakeResp(200, {"data": [{"sha256": "abc"}]})])
    assert client.binary_by_hash(sha256="abc")["data"][0]["sha256"] == "abc"
