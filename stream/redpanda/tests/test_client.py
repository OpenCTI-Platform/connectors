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
