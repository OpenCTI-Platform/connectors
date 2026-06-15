from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import requests
from swimlane_client import SwimlaneClient


def _make_client() -> SwimlaneClient:
    swimlane = SimpleNamespace(
        api_base_url="https://swimlane.example.com",
        api_token=SimpleNamespace(get_secret_value=lambda: "tok"),
        application_id="app-123",
        max_records=100,
        ssl_verify=True,
    )
    client = SwimlaneClient(SimpleNamespace(swimlane=swimlane), MagicMock())
    client.session = MagicMock()
    return client


def _response(payload) -> MagicMock:
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = payload
    response.raise_for_status.return_value = None
    return response


def test_extract_records_variants():
    assert SwimlaneClient._extract_records([{"id": "1"}]) == [{"id": "1"}]
    assert SwimlaneClient._extract_records({"results": [{"id": "2"}]}) == [{"id": "2"}]
    assert SwimlaneClient._extract_records({"docs": [{"id": "3"}]}) == [{"id": "3"}]
    assert SwimlaneClient._extract_records({"unexpected": 1}) == []


def test_get_records_posts_search():
    client = _make_client()
    client.session.request.return_value = _response({"results": [{"id": "1"}]})

    records = client.get_records()
    assert records == [{"id": "1"}]
    call = client.session.request.call_args
    assert call.args[0] == "post"
    assert call.args[1].endswith("/api/app/app-123/record/search")
    assert call.kwargs["json"]["pageSize"] == 100


def test_get_records_returns_empty_on_error():
    client = _make_client()
    client.session.request.side_effect = requests.RequestException("boom")
    with patch("swimlane_client.api_client.time.sleep"):
        assert client.get_records() == []


def test_request_retries_on_rate_limit():
    client = _make_client()
    rate_limited = MagicMock()
    rate_limited.status_code = 429
    client.session.request.side_effect = [rate_limited, _response({})]

    with patch("swimlane_client.api_client.time.sleep") as sleep:
        result = client._request("post", "/api/app/app-123/record/search", json={})

    assert result is not None
    assert client.session.request.call_count == 2
    sleep.assert_called_once()


def test_request_fails_fast_on_4xx_without_retry():
    client = _make_client()
    unauthorized = MagicMock()
    unauthorized.status_code = 401
    unauthorized.raise_for_status.side_effect = requests.HTTPError("401")
    client.session.request.return_value = unauthorized

    with patch("swimlane_client.api_client.time.sleep") as sleep:
        assert (
            client._request("post", "/api/app/app-123/record/search", json={}) is None
        )

    # No retry on a non-retriable 4xx: a single call and no backoff sleep.
    assert client.session.request.call_count == 1
    sleep.assert_not_called()


def test_request_retries_on_server_error():
    client = _make_client()
    server_error = MagicMock()
    server_error.status_code = 503
    client.session.request.side_effect = [server_error, _response({})]

    with patch("swimlane_client.api_client.time.sleep") as sleep:
        assert (
            client._request("post", "/api/app/app-123/record/search", json={})
            is not None
        )

    assert client.session.request.call_count == 2
    sleep.assert_called_once()
