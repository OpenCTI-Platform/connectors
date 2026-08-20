from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import requests
from clickhouse_client import ClickHouseClient


def _make_client(create_table: bool = True) -> ClickHouseClient:
    clickhouse = SimpleNamespace(
        base_url="http://clickhouse:8123",
        username="default",
        password=SimpleNamespace(get_secret_value=lambda: "pw"),
        database="default",
        table="opencti_stream",
        create_table=create_table,
        ssl_verify=True,
    )
    client = ClickHouseClient(SimpleNamespace(clickhouse=clickhouse), MagicMock())
    client.session = MagicMock()
    return client


def _response(status: int = 200) -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.raise_for_status.return_value = None
    return response


def test_ensure_table_runs_ddl():
    client = _make_client(create_table=True)
    client.session.post.return_value = _response(200)

    assert client.ensure_table() is True
    assert client.session.post.call_count == 2  # create database + create table


def test_ensure_table_skipped_when_disabled():
    client = _make_client(create_table=False)

    assert client.ensure_table() is True
    client.session.post.assert_not_called()


def test_ensure_table_returns_false_on_failure():
    client = _make_client(create_table=True)
    client.session.post.side_effect = requests.RequestException("boom")

    with patch("clickhouse_client.api_client.time.sleep"):
        assert client.ensure_table() is False


def test_insert_event_posts_row():
    client = _make_client()
    client.session.post.return_value = _response(200)

    assert client.insert_event("create", {"id": "x--1", "type": "indicator"}) is True
    call = client.session.post.call_args
    assert (
        "INSERT INTO default.opencti_stream FORMAT JSONEachRow"
        in call.kwargs["params"]["query"]
    )
    assert call.kwargs["data"] is not None


def test_insert_event_stores_explicit_event_date():
    import json

    client = _make_client()
    client.session.post.return_value = _response(200)

    assert (
        client.insert_event("create", {"id": "x--1", "type": "indicator"}, 1700000000)
        is True
    )
    row = json.loads(client.session.post.call_args.kwargs["data"].decode("utf-8"))
    assert row["event_date"] == 1700000000


def test_insert_event_returns_false_on_error():
    client = _make_client()
    client.session.post.side_effect = requests.RequestException("boom")

    with patch("clickhouse_client.api_client.time.sleep"):
        assert (
            client.insert_event("create", {"id": "x--1", "type": "indicator"}) is False
        )


def test_request_retries_on_rate_limit():
    client = _make_client()
    client.session.post.side_effect = [_response(429), _response(200)]

    with patch("clickhouse_client.api_client.time.sleep") as sleep:
        result = client._request(params={"query": "SELECT 1"})

    assert result is not None
    assert client.session.post.call_count == 2
    sleep.assert_called_once()


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

    with patch("clickhouse_client.api_client.time.sleep") as sleep:
        result = client._request(params={"query": "SELECT 1"})

    assert result is None
    assert client.session.post.call_count == 1
    sleep.assert_not_called()


def test_request_retries_on_server_error():
    # 5xx responses are transient and must be retried up to REQUEST_ATTEMPTS.
    client = _make_client()
    client.session.post.return_value = _http_error_response(500)

    with patch("clickhouse_client.api_client.time.sleep"):
        result = client._request(params={"query": "SELECT 1"})

    assert result is None
    assert client.session.post.call_count == ClickHouseClient.REQUEST_ATTEMPTS
