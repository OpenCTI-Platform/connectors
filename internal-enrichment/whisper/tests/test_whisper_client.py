import logging

import pytest
import requests
import responses
from connector.exceptions import (
    WhisperAuthError,
    WhisperQueryError,
    WhisperTransportError,
)
from connector.whisper_client import CypherResult, WhisperClient

URL = "https://api.whisper.test/api/query"


def _ok(rows=None, columns=None, statistics=None):
    """Build a minimal valid Whisper response body."""
    return {
        "success": True,
        "columns": columns if columns is not None else [],
        "rows": rows if rows is not None else [],
        "statistics": statistics if statistics is not None else {},
    }


@pytest.fixture
def client():
    # Disable retry backoff in tests so they run fast.
    return WhisperClient(
        api_url="https://api.whisper.test",
        api_key="test-key",
        max_retries=2,
        backoff_factor=0,
    )


@responses.activate
def test_execute_cypher_success_returns_full_result(client):
    body = _ok(
        columns=["n", "r", "m"],
        rows=[
            {
                "n": {"nodeId": "1", "label": "IPV4", "name": "8.8.8.8"},
                "r": {"type": "BELONGS_TO"},
                "m": {
                    "nodeId": "2",
                    "label": "REGISTERED_PREFIX",
                    "name": "8.8.8.0/24",
                },
            }
        ],
        statistics={"rowCount": 1, "executionTimeMs": 3},
    )
    responses.add(responses.POST, URL, json=body, status=200)

    result = client.execute_cypher("MATCH (n)-[r]-(m) RETURN n, r, m LIMIT 1")
    assert isinstance(result, CypherResult)
    assert result.columns == ["n", "r", "m"]
    assert len(result.rows) == 1
    assert result.rows[0]["n"]["name"] == "8.8.8.8"
    assert result.statistics == {"rowCount": 1, "executionTimeMs": 3}


@responses.activate
def test_execute_cypher_defaults_when_optional_fields_missing(client):
    # Body without `columns` or `statistics` should still parse cleanly.
    responses.add(responses.POST, URL, json={"success": True, "rows": []}, status=200)
    result = client.execute_cypher("MATCH (n) RETURN n LIMIT 1")
    assert result.columns == []
    assert result.rows == []
    assert result.statistics == {}


@responses.activate
def test_execute_cypher_success_false_raises_query_error(client):
    responses.add(
        responses.POST,
        URL,
        json={"success": False, "error": "syntax error at position 7", "rows": []},
        status=200,
    )
    with pytest.raises(WhisperQueryError, match="success=false"):
        client.execute_cypher("BAD")


@responses.activate
def test_execute_cypher_sends_api_key_header(client):
    responses.add(responses.POST, URL, json=_ok(), status=200)
    client.execute_cypher("MATCH (n) RETURN n")
    assert responses.calls[0].request.headers["X-API-Key"] == "test-key"


@responses.activate
def test_execute_cypher_sends_query_and_params(client):
    responses.add(responses.POST, URL, json=_ok(), status=200)
    client.execute_cypher("MATCH (n {name: $name}) RETURN n", {"name": "8.8.8.8"})
    body = responses.calls[0].request.body
    assert b'"query":' in body
    assert (
        b'"params": {"name": "8.8.8.8"}' in body
        or b'"params":{"name":"8.8.8.8"}' in body
    )


@responses.activate
def test_execute_cypher_401_raises_auth_error(client):
    responses.add(responses.POST, URL, json={"error": "bad key"}, status=401)
    with pytest.raises(WhisperAuthError):
        client.execute_cypher("MATCH (n) RETURN n")


@responses.activate
def test_execute_cypher_403_raises_auth_error(client):
    responses.add(responses.POST, URL, json={"error": "forbidden"}, status=403)
    with pytest.raises(WhisperAuthError):
        client.execute_cypher("MATCH (n) RETURN n")


@responses.activate
def test_execute_cypher_400_raises_query_error(client):
    responses.add(responses.POST, URL, json={"error": "bad cypher"}, status=400)
    with pytest.raises(WhisperQueryError):
        client.execute_cypher("BAD")


@responses.activate
def test_execute_cypher_5xx_retried_then_raises_transport_error(client):
    # max_retries=2 → 1 initial + 2 retries = 3 attempts total
    for _ in range(3):
        responses.add(responses.POST, URL, json={"error": "internal"}, status=503)
    with pytest.raises(WhisperTransportError):
        client.execute_cypher("MATCH (n) RETURN n")
    assert len(responses.calls) == 3


@responses.activate
def test_execute_cypher_recovers_after_5xx_then_200(client):
    responses.add(responses.POST, URL, status=503)
    responses.add(responses.POST, URL, json=_ok(rows=[{"ok": True}]), status=200)
    result = client.execute_cypher("MATCH (n) RETURN n")
    assert result.rows == [{"ok": True}]
    assert len(responses.calls) == 2


@responses.activate
def test_execute_cypher_connection_error_raises_transport_error(client):
    for _ in range(3):
        responses.add(
            responses.POST, URL, body=requests.ConnectionError("network down")
        )
    with pytest.raises(WhisperTransportError):
        client.execute_cypher("MATCH (n) RETURN n")


@responses.activate
def test_execute_cypher_non_json_body_raises_query_error(client):
    responses.add(responses.POST, URL, body="not json", status=200)
    with pytest.raises(WhisperQueryError):
        client.execute_cypher("MATCH (n) RETURN n")


@responses.activate
def test_execute_cypher_unexpected_rows_shape_raises_query_error(client):
    responses.add(
        responses.POST,
        URL,
        json={"success": True, "rows": {"not": "a list"}},
        status=200,
    )
    with pytest.raises(WhisperQueryError, match="'rows' shape"):
        client.execute_cypher("MATCH (n) RETURN n")


@responses.activate
def test_execute_cypher_unexpected_columns_shape_raises_query_error(client):
    responses.add(
        responses.POST,
        URL,
        json={"success": True, "rows": [], "columns": "not a list"},
        status=200,
    )
    with pytest.raises(WhisperQueryError, match="'columns' shape"):
        client.execute_cypher("MATCH (n) RETURN n")


@responses.activate
def test_api_key_never_logged(client, caplog):
    responses.add(responses.POST, URL, json=_ok(), status=200)
    with caplog.at_level(logging.DEBUG, logger="connector.whisper_client"):
        client.execute_cypher("MATCH (n) RETURN n")
    for record in caplog.records:
        assert "test-key" not in record.getMessage()


def test_init_rejects_empty_url():
    with pytest.raises(ValueError):
        WhisperClient(api_url="", api_key="x")


def test_init_rejects_empty_key():
    with pytest.raises(ValueError):
        WhisperClient(api_url="https://x", api_key="")


def test_init_strips_trailing_slash():
    c = WhisperClient(api_url="https://api.whisper.test/", api_key="k")
    assert c.api_url == "https://api.whisper.test"


@responses.activate
def test_context_manager_closes_session(client):
    responses.add(responses.POST, URL, json=_ok(), status=200)
    with client as c:
        c.execute_cypher("MATCH (n) RETURN n")
    # Session is closed; another request would re-open connections but the
    # session object itself should still be usable post-close. Just verify
    # no exception leaked from __exit__.


# --- 429-aware backoff (issue #30) ----------------------------------------


@responses.activate
def test_execute_cypher_429_retried_then_recovers_after_200(client):
    # Three consecutive 429s with Retry-After: 0 (instant, keeps the test
    # fast) followed by a 200 — urllib3 should burn through the 429s and
    # surface the 200 body without raising.
    for _ in range(3):
        responses.add(
            responses.POST,
            URL,
            json={"error": "rate limited"},
            status=429,
            headers={"Retry-After": "0"},
        )
    responses.add(responses.POST, URL, json=_ok(rows=[{"ok": True}]), status=200)

    # The default client fixture caps retries at 2; we need at least 3 retries
    # to clear three 429s before reaching the 200. Build a dedicated client.
    c = WhisperClient(
        api_url="https://api.whisper.test",
        api_key="test-key",
        max_retries=3,
        backoff_factor=0,
    )
    result = c.execute_cypher("MATCH (n) RETURN n")
    assert result.rows == [{"ok": True}]
    assert len(responses.calls) == 4


@responses.activate
def test_execute_cypher_quota_exhaustion_raises_transport_error(client):
    # Issue #30 AC: ten 429s in a row (i.e. retries exhausted) must raise
    # WhisperTransportError, NOT WhisperQueryError. The error-class
    # distinction is what lets QA bucket this as a quota incident instead
    # of a malformed-Cypher bug.
    for _ in range(10):
        responses.add(
            responses.POST,
            URL,
            json={"error": "rate limited"},
            status=429,
            headers={"Retry-After": "0"},
        )
    with pytest.raises(WhisperTransportError, match="rate-limited"):
        client.execute_cypher("MATCH (n) RETURN n")


@responses.activate
def test_execute_cypher_429_emits_info_log_per_retry(caplog):
    # Each retry on a 429 should produce one info-level log line so admins
    # can correlate quota spikes with enrichment failures. Three 429s →
    # three info lines, then a 200 closes out cleanly.
    for _ in range(3):
        responses.add(
            responses.POST,
            URL,
            status=429,
            headers={"Retry-After": "0"},
        )
    responses.add(responses.POST, URL, json=_ok(), status=200)

    c = WhisperClient(
        api_url="https://api.whisper.test",
        api_key="test-key",
        max_retries=3,
        backoff_factor=0,
    )
    with caplog.at_level(logging.INFO, logger="connector.whisper_client"):
        c.execute_cypher("MATCH (n) RETURN n")
    rate_limit_lines = [
        r for r in caplog.records if "rate-limited (HTTP 429)" in r.getMessage()
    ]
    assert len(rate_limit_lines) == 3
    assert all(r.levelname == "INFO" for r in rate_limit_lines)
    # Retry-After value must surface in the log so admins can see how long
    # Whisper asked us to back off for.
    assert all("Retry-After=0" in r.getMessage() for r in rate_limit_lines)
