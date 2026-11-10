"""Tests for how the account quota reader is wired into the sandbox connector."""

import threading
from unittest.mock import MagicMock

import pytest
from connector.quota import QuotaMonitor
from polyswarm_api import exceptions as polyswarm_exceptions

from tests.test_quota import FakeClock, FakeLogger, _account


def _sdk_client(quota_api):
    """A PolySwarmClient with a mocked SDK and a quota monitor on a fake account."""
    from connector.polyswarm_client import CircuitBreaker, PolySwarmClient

    client = PolySwarmClient.__new__(PolySwarmClient)
    client.helper = MagicMock()
    client.api = MagicMock()
    client._session = MagicMock()
    client._breaker = CircuitBreaker(failure_threshold=3, cooldown_seconds=0)
    client.SDK_MAX_RETRIES = 2
    client.SDK_BACKOFF_BASE = 0.01
    client.quota = QuotaMonitor(quota_api, FakeLogger(), clock=FakeClock())
    return client


class TestClientWiring:
    def test_sdk_429_raises_quota_exhausted_with_remaining_quota(self):
        from connector.polyswarm_client import PolySwarmAPIError

        quota_api = MagicMock()
        quota_api.account_features.return_value = _account(limit=500, remaining=0)
        client = _sdk_client(quota_api)
        client.api.submit = MagicMock(
            side_effect=polyswarm_exceptions.UsageLimitsExceededException(
                None, "You have exceeded your allowance."
            )
        )
        with pytest.raises(PolySwarmAPIError) as exc_info:
            client._retry_sdk_call(client.api.submit, operation="scan submit")
        error = exc_info.value
        assert error.category == "API Quota Exhausted (scan submit)"
        assert "Daily API calls remaining: 0 of 500" in error.detail
        assert "Usage window ends: 2026-12-01T00:00:00+00:00" in error.detail
        assert "000000000000" not in error.detail
        # Not retried: waiting seconds does not bring quota back
        assert client.api.submit.call_count == 1

    def test_quota_error_still_raised_when_quota_cannot_be_read(self):
        from connector.polyswarm_client import PolySwarmAPIError

        quota_api = MagicMock()
        quota_api.account_features.side_effect = ConnectionError("down")
        client = _sdk_client(quota_api)
        client.api.submit = MagicMock(
            side_effect=polyswarm_exceptions.UsageLimitsExceededException(None, "x")
        )
        with pytest.raises(PolySwarmAPIError) as exc_info:
            client._retry_sdk_call(client.api.submit, operation="scan submit")
        assert "could not be read" in exc_info.value.detail

    def test_url_submission_429_names_quota_and_does_not_leak_the_url(self):
        from connector.polyswarm_client import PolySwarmAPIError

        quota_api = MagicMock()
        quota_api.account_features.return_value = _account(limit=500, remaining=0)
        client = _sdk_client(quota_api)
        secret_url = "https://example.test/path?token=SECRETVALUE"
        client.api.sandbox_url = MagicMock(
            side_effect=polyswarm_exceptions.UsageLimitsExceededException(
                None, f"limit exceeded for {secret_url}"
            )
        )
        with pytest.raises(PolySwarmAPIError) as exc_info:
            client.submit_sandbox_url_async(secret_url)
        error = exc_info.value
        assert "Quota Exhausted" in error.category
        assert "SECRETVALUE" not in f"{error.category} {error.detail}"
        assert "Daily API calls remaining: 0 of 500" in error.detail

    def test_error_note_carries_the_quota_lines(self):
        from connector.polyswarm_client import PolySwarmAPIError
        from connector.stix_builder import StixBuilder

        quota_api = MagicMock()
        quota_api.account_features.return_value = _account(limit=500, remaining=0)
        client = _sdk_client(quota_api)
        error = client._quota_exhausted_error("scan submit")
        assert isinstance(error, PolySwarmAPIError)
        builder = StixBuilder(helper=MagicMock(), polykg_api_url=None)
        note = builder.create_error_note(
            {"id": "artifact--00000000-0000-4000-8000-000000000000"},
            error.category,
            error.detail,
            error.recommendations,
        )
        assert "Daily API calls remaining: 0 of 500" in note["content"]
        assert "Wait for your quota to reset" in note["content"]


class TestPollingWiring:
    @pytest.mark.parametrize(
        "method,sdk_call,arg",
        [
            ("get_scan_results", "lookup", "scan-1"),
            ("get_sandbox_results", "sandbox_task_status", "task-1"),
        ],
    )
    def test_429_while_polling_surfaces_as_the_quota_error(self, method, sdk_call, arg):
        from connector.polyswarm_client import PolySwarmAPIError

        quota_api = MagicMock()
        quota_api.account_features.return_value = _account(limit=500, remaining=0)
        client = _sdk_client(quota_api)
        setattr(
            client.api,
            sdk_call,
            MagicMock(
                side_effect=polyswarm_exceptions.UsageLimitsExceededException(None, "x")
            ),
        )
        with pytest.raises(PolySwarmAPIError) as exc_info:
            getattr(client, method)(arg)
        assert "Quota Exhausted" in exc_info.value.category
        assert "Daily API calls remaining: 0 of 500" in exc_info.value.detail


class TestConnectorWiring:
    def test_each_message_refreshes_the_quota(self):
        from connector.polyswarm_connector import PolySwarmConnector

        connector = object.__new__(PolySwarmConnector)
        connector.helper = MagicMock()
        connector.polyswarm_client = MagicMock()
        connector.stix_builder = MagicMock()
        connector._local = threading.local()
        result = connector._process_message({"stix_objects": []})
        connector.polyswarm_client.quota.refresh.assert_called_once_with()
        assert "Entity not found" in result


class TestSettings:
    def test_quota_warn_below_default_and_env(self, monkeypatch):
        ConnectorSettings = pytest.importorskip(
            "connector.models.configs.settings", reason="connectors_sdk unavailable"
        ).ConnectorSettings
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.setenv("CONNECTOR_ID", "00000000-0000-0000-0000-000000000006")
        monkeypatch.setenv("POLYSWARM_API_KEY", "test-key")
        assert ConnectorSettings().polyswarm.quota_warn_below == 100
        monkeypatch.setenv("POLYSWARM_QUOTA_WARN_BELOW", "0")
        assert ConnectorSettings().polyswarm.quota_warn_below == 0
