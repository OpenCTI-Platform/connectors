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
