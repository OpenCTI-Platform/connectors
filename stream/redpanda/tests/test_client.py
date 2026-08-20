from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import requests
from redpanda_client import RedpandaClient


def _make_client(username: str = "") -> RedpandaClient:
    redpanda = SimpleNamespace(
        http_proxy_url="http://redpanda:8082",
        topic="opencti",
        username=username,
        password=SimpleNamespace(get_secret_value=lambda: "pw"),
        ssl_verify=True,
    )
    client = RedpandaClient(SimpleNamespace(redpanda=redpanda), MagicMock())
    client.session = MagicMock()
    return client


def _response(status: int = 200) -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.raise_for_status.return_value = None
    return response


def test_produce_event_posts_record():
    client = _make_client()
    client.session.post.return_value = _response(200)

    assert client.produce_event("create", {"id": "x--1", "type": "indicator"}) is True
    call = client.session.post.call_args
    assert call.args[0] == "http://redpanda:8082/topics/opencti"
    assert call.kwargs["data"] is not None


def test_produce_event_uses_stix_id_as_key():
    import json

    client = _make_client()
    client.session.post.return_value = _response(200)

    client.produce_event("create", {"id": "indicator--1", "type": "indicator"})
    payload = json.loads(client.session.post.call_args.kwargs["data"].decode("utf-8"))
    assert payload["records"][0]["key"] == "indicator--1"


def test_produce_event_leaves_key_unset_when_id_missing_or_none():
    import json

    client = _make_client()
    client.session.post.return_value = _response(200)

    for data in ({"type": "indicator"}, {"id": None, "type": "indicator"}):
        client.produce_event("create", data)
        payload = json.loads(
            client.session.post.call_args.kwargs["data"].decode("utf-8")
        )
        assert payload["records"][0]["key"] is None


def test_produce_event_returns_false_on_error():
    client = _make_client()
    client.session.post.side_effect = requests.RequestException("boom")

    with patch("redpanda_client.api_client.time.sleep"):
        result = client.produce_event("create", {"id": "x--1", "type": "indicator"})

    assert result is False


def test_request_retries_on_rate_limit():
    client = _make_client()
    client.session.post.side_effect = [_response(429), _response(200)]

    with patch("redpanda_client.api_client.time.sleep") as sleep:
        result = client._request("http://redpanda:8082/topics/opencti", b"{}")

    assert result is not None
    assert client.session.post.call_count == 2
    sleep.assert_called_once()


def test_basic_auth_is_configured_when_username_provided():
    redpanda = SimpleNamespace(
        http_proxy_url="http://redpanda:8082",
        topic="opencti",
        username="user",
        password=SimpleNamespace(get_secret_value=lambda: "pw"),
        ssl_verify=True,
    )
    # Build with the real requests.Session created in __init__ (no session mock).
    client = RedpandaClient(SimpleNamespace(redpanda=redpanda), MagicMock())
    assert client.session.auth == ("user", "pw")


def _http_error_response(status: int) -> MagicMock:
    response = _response(status)
    error = requests.HTTPError(f"{status} error")
    error.response = response
    response.raise_for_status.side_effect = error
    return response


def test_request_does_not_retry_on_client_error():
    # Non-429 4xx responses are not retriable: fail fast without backoff.
    client = _make_client()
    client.session.post.return_value = _http_error_response(401)

    with patch("redpanda_client.api_client.time.sleep") as sleep:
        result = client._request("http://redpanda:8082/topics/opencti", b"{}")

    assert result is None
    assert client.session.post.call_count == 1
    sleep.assert_not_called()


def test_request_retries_on_server_error():
    # 5xx responses are transient and must be retried up to REQUEST_ATTEMPTS.
    client = _make_client()
    client.session.post.return_value = _http_error_response(500)

    with patch("redpanda_client.api_client.time.sleep"):
        result = client._request("http://redpanda:8082/topics/opencti", b"{}")

    assert result is None
    assert client.session.post.call_count == RedpandaClient.REQUEST_ATTEMPTS
