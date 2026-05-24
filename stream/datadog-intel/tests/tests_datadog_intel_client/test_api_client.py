import gzip
import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests
import requests_mock as requests_mock_lib
from connector import ConnectorSettings
from datadog_intel_client import DatadogIntelClient

_API_BASE_URL = "http://test.com"


class StubConnectorSettings(ConnectorSettings):
    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "live_stream_id": "live",
                    "live_stream_listen_delete": True,
                    "live_stream_no_dependencies": True,
                },
                "datadog_intel": {
                    "integration_api_url": _API_BASE_URL,
                    "dd_api_key": "test-api-key",
                    "dd_application_key": "test-app-key",
                },
            }
        )


@pytest.fixture
def config():
    return StubConnectorSettings()


@pytest.fixture
def helper():
    h = MagicMock()
    h.connector_logger = MagicMock()
    return h


@pytest.fixture
def client(config, helper):
    return DatadogIntelClient(helper, config, "ip_address")


def test_post_indicators_sends_gzipped_payload(client):
    payload = {"indicators": [{"type": "ip", "value": "1.2.3.4"}]}

    with requests_mock_lib.Mocker() as m:
        m.post(_API_BASE_URL, status_code=200)
        client._post_indicators(json.dumps(payload))

        request_body = m.last_request.body
        assert isinstance(request_body, bytes)
        assert json.loads(gzip.decompress(request_body)) == payload
        assert m.last_request.headers["Content-Encoding"] == "gzip"


def test_post_indicators_sends_dd_auth_headers(client):
    with requests_mock_lib.Mocker() as m:
        m.post(_API_BASE_URL, status_code=200)
        client._post_indicators(json.dumps({}))

        assert m.last_request.headers["dd-api-key"] == "test-api-key"
        assert m.last_request.headers["dd-application-key"] == "test-app-key"


def test_post_indicators_sends_ti_indicator_header(helper, config):
    domain_client = DatadogIntelClient(helper, config, "domain")

    with requests_mock_lib.Mocker() as m:
        m.post(_API_BASE_URL, status_code=200)
        domain_client._post_indicators(json.dumps({}))

        assert m.last_request.headers["ti_indicator"] == "domain"


###########################################################
# Flush batch retry tests
###########################################################


@pytest.fixture(autouse=False)
def instant_retry():
    """Make tenacity retries instant by removing the sleep between attempts."""
    with patch.object(
        DatadogIntelClient._post_indicators.retry, "sleep", lambda _: None
    ):
        yield


def test_flush_batch_success(client):
    client.batch = {"id-1": {"id": "id-1"}, "id-2": {"id": "id-2"}}

    with requests_mock_lib.Mocker() as m:
        m.post(_API_BASE_URL, status_code=200)
        client._flush_batch()

    assert client.batch == {}


def test_flush_batch_success_after_two_failures(client, instant_retry):
    client.batch = {"id-1": {"id": "id-1"}}

    with requests_mock_lib.Mocker() as m:
        m.post(
            _API_BASE_URL,
            [
                {"exc": requests.ConnectionError("timeout")},
                {"exc": requests.ConnectionError("timeout")},
                {"status_code": 200},
            ],
        )
        client._flush_batch()

    assert client.batch == {}


def test_flush_batch_all_attempts_failed_batch_retained(client, instant_retry):
    client.batch = {"id-1": {"id": "id-1"}, "id-2": {"id": "id-2"}}

    with requests_mock_lib.Mocker() as m:
        m.post(_API_BASE_URL, exc=requests.ConnectionError("timeout"))
        client._flush_batch()

    assert len(client.batch) == 2


def test_flush_batch_all_attempts_failed_batch_dropped_at_limit(client, instant_retry):
    client.batch = {"id-1": {"id": "id-1"}, "id-2": {"id": "id-2"}}

    with patch("datadog_intel_client.api_client.BATCH_SIZE", 2):
        with requests_mock_lib.Mocker() as m:
            m.post(_API_BASE_URL, exc=requests.ConnectionError("timeout"))
            client._flush_batch()

    assert client.batch == {}


def test_flush_batch_sends_single_request_for_multiple_indicators(helper, config):
    ip_client = DatadogIntelClient(helper, config, "ip_address")

    for i in range(1, 3):
        ip_client._append_to_batch(
            {
                "id": f"ip-{i}",
                "modified": "2024-01-01T00:00:00Z",
                "x_opencti_event_type": "create",
                "extensions": {
                    "ext-1": {"id": f"ip-{i}", "main_observable_type": "IPv4-Addr"}
                },
            }
        )

    with requests_mock_lib.Mocker() as m:
        m.post(_API_BASE_URL, status_code=200)
        ip_client._flush_batch()

    assert m.call_count == 1
    assert m.request_history[0].headers["ti_indicator"] == "ip_address"
    assert ip_client.batch == {}


###########################################################
# Lock semantics: HTTP POST must not block ``_append_to_batch``
###########################################################
#
# Regression test for the Copilot review thread on
# ``api_client.py:126``. The previous shape held ``batch_lock`` for
# the full retry cycle (up to ~60 s of exponential backoff during a
# Datadog outage), blocking every incoming ``_append_to_batch`` call.
# The fix snapshots the batch under the lock, releases it before the
# POST, then re-acquires only to clean up sent entries (without
# clobbering new arrivals).


def test_append_can_proceed_concurrently_with_in_flight_post(client):
    """``_append_to_batch`` MUST proceed while a flush's HTTP POST is in flight."""
    import threading
    import time

    client.batch = {
        "id-1": {
            "id": "id-1",
            "modified": "2024-01-01T00:00:00Z",
            "x_opencti_event_type": "create",
            "extensions": {
                "ext-1": {"id": "id-1", "main_observable_type": "IPv4-Addr"}
            },
        }
    }

    post_entered = threading.Event()
    release_post = threading.Event()
    append_done = threading.Event()

    original_post = client.session.post

    def slow_post(*args, **kwargs):
        post_entered.set()
        # Wait until the test signals we may complete the POST. The
        # ``_append_to_batch`` thread should be able to run during
        # this wait — that is the contract under test.
        assert release_post.wait(timeout=5), "test deadlock"
        return original_post(*args, **kwargs)

    def append_when_post_in_flight():
        # Block until the flush thread is inside the HTTP POST, then
        # append a new event. The append must complete promptly
        # (well before the post releases) — if the lock is still held
        # during the POST, this thread will deadlock-block until
        # ``release_post`` is set, and ``append_done`` won't fire in
        # the short window the assertion below allows.
        assert post_entered.wait(timeout=5), "post never entered"
        client._append_to_batch(
            {
                "id": "id-2",
                "modified": "2024-01-01T00:00:01Z",
                "x_opencti_event_type": "create",
                "extensions": {
                    "ext-1": {"id": "id-2", "main_observable_type": "IPv4-Addr"}
                },
            }
        )
        append_done.set()

    with requests_mock_lib.Mocker() as m:
        m.post(_API_BASE_URL, status_code=200)
        client.session.post = slow_post  # type: ignore[assignment]
        try:
            flush_t = threading.Thread(target=client._flush_batch)
            append_t = threading.Thread(target=append_when_post_in_flight)
            flush_t.start()
            append_t.start()
            assert append_done.wait(timeout=2), (
                "append did not complete while POST was in flight — "
                "_flush_batch is still holding batch_lock across the HTTP call"
            )
            release_post.set()
            flush_t.join(timeout=5)
            append_t.join(timeout=5)
            assert not flush_t.is_alive()
            assert not append_t.is_alive()
        finally:
            client.session.post = original_post  # type: ignore[assignment]

    # The flush sent the snapshot (``id-1``); ``id-2`` arrived during
    # the POST so it must remain in the batch for the next flush
    # (not silently dropped by an over-eager ``self.batch = {}`` at
    # the end of the flush).
    assert "id-1" not in client.batch
    assert "id-2" in client.batch
    # Sanity: only one POST request was made for the snapshot we
    # captured before the late-arriving append.
    assert m.call_count == 1

    # silence unused import lints
    _ = time


def test_flush_preserves_concurrent_replacement(client):
    """An entry REPLACED during the POST must not be silently dropped."""
    client.batch = {
        "id-1": {
            "id": "id-1",
            "modified": "2024-01-01T00:00:00Z",
            "x_opencti_event_type": "create",
            "extensions": {
                "ext-1": {"id": "id-1", "main_observable_type": "IPv4-Addr"}
            },
        }
    }

    def replace_id1_then_succeed(request, context):
        # Simulate an upstream update arriving during the HTTP POST —
        # ``_append_to_batch`` would assign a fresh dict to the same
        # key. The post-flush cleanup must detect this via identity
        # comparison and keep the new state for the next flush.
        client.batch["id-1"] = {
            "id": "id-1",
            "modified": "2024-01-01T00:00:01Z",
            "x_opencti_event_type": "update",
            "extensions": {
                "ext-1": {"id": "id-1", "main_observable_type": "IPv4-Addr"}
            },
        }
        context.status_code = 200
        return ""

    with requests_mock_lib.Mocker() as m:
        m.post(_API_BASE_URL, text=replace_id1_then_succeed)
        client._flush_batch()

    # The update that arrived during the POST is retained.
    assert "id-1" in client.batch
    assert client.batch["id-1"]["x_opencti_event_type"] == "update"
