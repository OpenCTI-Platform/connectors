"""Tests for the PolySwarm live hunting client against a local HTTP server."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest
from polyswarm_client.hunting_client import (
    LIVE_HUNT_LIST_PATH,
    MAX_PAGE_SIZE,
    PolySwarmHuntingAuthError,
    PolySwarmHuntingClient,
    PolySwarmHuntingError,
)

FAKE_KEY = "0" * 32


class _FakeApi:
    """Serves scripted responses in order and records every request."""

    def __init__(self):
        self.responses = []
        self.requests = []
        api = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 (http.server naming)
                parsed = urlparse(self.path)
                api.requests.append(
                    {
                        "path": parsed.path,
                        "query": {k: v[0] for k, v in parse_qs(parsed.query).items()},
                        "authorization": self.headers.get("Authorization"),
                    }
                )
                if api.responses:
                    status, body, headers = api.responses.pop(0)
                else:
                    status, body, headers = 500, {"result": "no scripted reply"}, {}
                payload = b"" if body is None else json.dumps(body).encode()
                self.send_response(status)
                if body is not None:
                    self.send_header("Content-Type", "application/json")
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def reply(self, status, body=None, headers=None):
        self.responses.append((status, body, headers or {}))

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def api():
    fake = _FakeApi()
    yield fake
    fake.close()


def _client(api, **kwargs):
    kwargs.setdefault("backoff_factor", 0)
    kwargs.setdefault("timeout", 5)
    return PolySwarmHuntingClient(api.url, FAKE_KEY, **kwargs)


def _page(ids, has_more=False, offset=None):
    body = {
        "has_more": has_more,
        "limit": MAX_PAGE_SIZE,
        "result": [{"id": str(i), "sha256": "a" * 64} for i in ids],
        "status": "OK",
    }
    if offset is not None:
        body["offset"] = offset
    return body


def test_single_page_request_shape(api):
    api.reply(200, _page([1, 2]))
    hits = _client(api).list_live_hits(600)
    assert [h["id"] for h in hits] == ["1", "2"]
    request = api.requests[0]
    assert request["path"] == LIVE_HUNT_LIST_PATH
    assert request["query"] == {"since": "600", "limit": str(MAX_PAGE_SIZE)}
    # Raw key, no "Bearer" prefix.
    assert request["authorization"] == FAKE_KEY


def test_paging_follows_offset_cursor(api):
    api.reply(200, _page([1, 2], has_more=True, offset="cursor-1"))
    api.reply(200, _page([3], has_more=True, offset="cursor-2"))
    api.reply(200, _page([4], has_more=False))
    hits = _client(api).list_live_hits(3600)
    assert [h["id"] for h in hits] == ["1", "2", "3", "4"]
    assert "offset" not in api.requests[0]["query"]
    assert api.requests[1]["query"]["offset"] == "cursor-1"
    assert api.requests[2]["query"]["offset"] == "cursor-2"
    assert all(r["query"]["since"] == "3600" for r in api.requests)


def test_204_is_empty(api):
    api.reply(204)
    assert _client(api).list_live_hits(600) == []
    assert len(api.requests) == 1


def test_null_result_is_empty(api):
    api.reply(200, {"has_more": False, "result": None, "status": "OK"})
    assert _client(api).list_live_hits(600) == []


def test_has_more_without_cursor_stops(api):
    api.reply(200, _page([1], has_more=True))
    assert [h["id"] for h in _client(api).list_live_hits(600)] == ["1"]
    assert len(api.requests) == 1


def test_repeated_cursor_stops(api):
    api.reply(200, _page([1], has_more=True, offset="same"))
    api.reply(200, _page([2], has_more=True, offset="same"))
    api.reply(200, _page([3]))
    assert [h["id"] for h in _client(api).list_live_hits(600)] == ["1", "2"]
    assert len(api.requests) == 2


def test_max_pages_bound(api):
    for n in range(5):
        api.reply(200, _page([n], has_more=True, offset=f"c{n}"))
    hits = _client(api, max_pages=3).list_live_hits(600)
    assert len(hits) == 3
    assert len(api.requests) == 3


def test_non_dict_items_are_ignored(api):
    api.reply(200, {"has_more": False, "result": [{"id": "1"}, "junk", None]})
    assert _client(api).list_live_hits(600) == [{"id": "1"}]


def test_retries_on_429_then_succeeds(api):
    api.reply(429, {"result": "slow down"}, {"Retry-After": "0"})
    api.reply(200, _page([1]))
    assert len(_client(api).list_live_hits(600)) == 1
    assert len(api.requests) == 2


def test_retries_on_5xx_then_succeeds(api):
    api.reply(502, {"result": "bad gateway"})
    api.reply(503, {"result": "unavailable"})
    api.reply(200, _page([1]))
    assert len(_client(api).list_live_hits(600)) == 1
    assert len(api.requests) == 3


def test_5xx_after_retries_raises(api):
    for _ in range(4):
        api.reply(500, {"errors": None, "result": "Something went wrong"})
    with pytest.raises(PolySwarmHuntingError) as err:
        _client(api, max_retries=2).list_live_hits(600)
    assert "500" in str(err.value)
    assert len(api.requests) == 3


@pytest.mark.parametrize("status", [401, 403])
def test_auth_errors_are_clear(api, status):
    api.reply(status, {"result": "Unauthorized: API Key is required."})
    with pytest.raises(PolySwarmHuntingAuthError) as err:
        _client(api).list_live_hits(600)
    message = str(err.value)
    assert "API key" in message
    assert "POLYSWARM_API_KEY" in message
    assert FAKE_KEY not in message
    assert err.value.status_code == status
    assert len(api.requests) == 1


def test_malformed_key_400_is_auth_error(api):
    # Measured: a key that is not 32 alphanumerics gets a 400, not a 401.
    api.reply(400, {"result": "API Key must be a 32 character alphanumeric string"})
    with pytest.raises(PolySwarmHuntingAuthError):
        _client(api).list_live_hits(600)


def test_other_400_is_plain_error_with_server_message(api):
    api.reply(400, {"result": "offset is not a valid pagination cursor"})
    with pytest.raises(PolySwarmHuntingError) as err:
        _client(api).list_live_hits(600)
    assert not isinstance(err.value, PolySwarmHuntingAuthError)
    assert "offset is not a valid pagination cursor" in str(err.value)


def test_non_object_body_raises(api):
    api.reply(200, ["not", "an", "object"])
    with pytest.raises(PolySwarmHuntingError):
        _client(api).list_live_hits(600)


def test_result_not_a_list_raises(api):
    api.reply(200, {"has_more": False, "result": "oops"})
    with pytest.raises(PolySwarmHuntingError):
        _client(api).list_live_hits(600)


@pytest.mark.parametrize("since", [0, -5, 1.5, "60", None, True])
def test_since_must_be_positive_int(api, since):
    with pytest.raises(ValueError):
        _client(api).list_live_hits(since)
    assert api.requests == []


def test_constructor_validation():
    with pytest.raises(ValueError):
        PolySwarmHuntingClient("https://example.invalid", "")
    with pytest.raises(ValueError):
        PolySwarmHuntingClient("https://example.invalid", FAKE_KEY, page_size=301)
    with pytest.raises(ValueError):
        PolySwarmHuntingClient("https://example.invalid", FAKE_KEY, page_size=0)


def test_base_url_trailing_slash(api):
    api.reply(204)
    PolySwarmHuntingClient(api.url + "/", FAKE_KEY, timeout=5).list_live_hits(60)
    assert api.requests[0]["path"] == LIVE_HUNT_LIST_PATH
