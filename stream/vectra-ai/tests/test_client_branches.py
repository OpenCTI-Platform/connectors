from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import requests
from vectra_client import VectraClient
from vectra_client.stix_builder import build_stix_package


def _make_client() -> VectraClient:
    vectra_ai = SimpleNamespace(
        api_base_url="https://vectra.example.com",
        api_token=SimpleNamespace(get_secret_value=lambda: "token"),
        api_version="v2.5",
        feed_name="OpenCTI",
        feed_category="cnc",
        feed_certainty="High",
        feed_duration=14,
        ssl_verify=True,
    )
    client = VectraClient(SimpleNamespace(vectra_ai=vectra_ai), MagicMock())
    client.session = MagicMock()
    return client


def _response(status: int = 200, payload: dict | None = None) -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.json.return_value = payload if payload is not None else {}
    response.raise_for_status.return_value = None
    return response


def test_request_retries_on_rate_limit():
    client = _make_client()
    client.session.request.side_effect = [_response(429), _response(200, {"ok": True})]

    with patch("vectra_client.api_client.time.sleep") as sleep:
        result = client._request(
            "get", "https://vectra.example.com/api/v2.5/threatFeeds"
        )

    assert result is not None
    assert client.session.request.call_count == 2
    sleep.assert_called_once()


def test_request_returns_none_on_persistent_error():
    client = _make_client()
    client.session.request.side_effect = requests.RequestException("boom")

    with patch("vectra_client.api_client.time.sleep"):
        result = client._request(
            "get", "https://vectra.example.com/api/v2.5/threatFeeds"
        )

    assert result is None
    assert client.session.request.call_count == VectraClient.REQUEST_ATTEMPTS


def test_find_feed_id_returns_none_when_absent():
    client = _make_client()
    client.session.request.return_value = _response(
        200, {"threatFeeds": [{"id": "1", "name": "SomethingElse"}]}
    )

    assert client._find_feed_id("OpenCTI") is None


def test_find_feed_id_returns_none_on_request_failure():
    client = _make_client()
    client.session.request.return_value = None
    with patch.object(client, "_request", return_value=None):
        assert client._find_feed_id("OpenCTI") is None


def test_create_feed_returns_none_on_empty_response():
    client = _make_client()
    client.session.request.return_value = _response(200, {})

    assert client._create_feed() is None


def test_add_indicator_returns_false_when_feed_unresolved():
    client = _make_client()
    with patch.object(client, "get_or_create_feed", return_value=None):
        result = client.add_indicator({"pattern": "[ipv4-addr:value = '198.51.100.1']"})

    assert result is False


def test_build_stix_package_rejects_unknown_type():
    with pytest.raises(ValueError):
        build_stix_package([("mutex", "evil")])


def test_find_feed_id_returns_none_when_match_missing_id():
    # A feed that matches by name but carries no id must not resolve to the
    # literal string "None" (which would build a "/threatFeeds/None" endpoint).
    client = _make_client()
    client.session.request.return_value = _response(
        200, {"threatFeeds": [{"name": "OpenCTI"}]}
    )

    assert client._find_feed_id("OpenCTI") is None


def _http_error_response(status: int) -> MagicMock:
    response = _response(status)
    error = requests.HTTPError(f"{status} error")
    error.response = response
    response.raise_for_status.side_effect = error
    return response


def test_request_does_not_retry_on_client_error():
    # Non-429 4xx responses are not retriable: fail fast without backoff.
    client = _make_client()
    client.session.request.return_value = _http_error_response(401)

    with patch("vectra_client.api_client.time.sleep") as sleep:
        result = client._request(
            "get", "https://vectra.example.com/api/v2.5/threatFeeds"
        )

    assert result is None
    assert client.session.request.call_count == 1
    sleep.assert_not_called()


def test_request_retries_on_server_error():
    # 5xx responses are transient and must be retried up to REQUEST_ATTEMPTS.
    client = _make_client()
    client.session.request.return_value = _http_error_response(500)

    with patch("vectra_client.api_client.time.sleep"):
        result = client._request(
            "get", "https://vectra.example.com/api/v2.5/threatFeeds"
        )

    assert result is None
    assert client.session.request.call_count == VectraClient.REQUEST_ATTEMPTS
