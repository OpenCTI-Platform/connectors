"""Resilience tests — verify graceful degradation under failure conditions.

Tests connector behavior when external services fail:
- API timeouts mid-request
- HTTP 500 errors during polling
- Network drops (ConnectionError)
- Partial/corrupt responses
- Circuit breaker recovery after cooldown
"""

import io
import os
import sys
import time

import pytest
from unittest.mock import MagicMock, patch

import requests

SRC_DIR = os.path.join(os.path.dirname(__file__), os.pardir, "src")
sys.path.insert(0, os.path.abspath(SRC_DIR))

from connector.polyswarm_client import CircuitBreaker, PolySwarmClient, PolySwarmAPIError

# ── Helpers ──────────────────────────────────────────────────────────────


def _make_client():
    """Create a PolySwarmClient with mocked SDK API."""
    client = PolySwarmClient.__new__(PolySwarmClient)
    client.helper = MagicMock()
    client.api = MagicMock()
    client._session = MagicMock()
    client._breaker = CircuitBreaker(failure_threshold=3, cooldown_seconds=0)
    client.SDK_MAX_RETRIES = 2
    client.SDK_BACKOFF_BASE = 0.01  # Fast retries for testing
    return client


# ── Timeout Resilience ───────────────────────────────────────────────────


class TestTimeoutResilience:
    """Connector must handle timeouts gracefully."""

    def test_scan_submit_timeout(self):
        client = _make_client()
        client.api.submit = MagicMock(side_effect=requests.Timeout("Connection timed out"))
        result = client.submit_file_async(b"test", "test.exe")
        assert result is None  # Should return None, not crash

    def test_sandbox_submit_timeout(self):
        client = _make_client()
        client.api.sandbox_file = MagicMock(side_effect=requests.Timeout("Timed out"))
        result = client.submit_sandbox_async(b"test", "test.exe")
        assert result is None

    def test_scan_results_timeout(self):
        client = _make_client()
        client.api.lookup = MagicMock(side_effect=requests.Timeout("Timed out"))
        result = client.get_scan_results("scan-123")
        assert result is None

    def test_sandbox_results_timeout(self):
        client = _make_client()
        client.api.sandbox_task_status = MagicMock(side_effect=requests.Timeout("Timed out"))
        result = client.get_sandbox_results("task-123")
        assert result is None


# ── HTTP 500 Resilience ──────────────────────────────────────────────────


class TestHTTP500Resilience:
    """Connector must retry on 500 errors and eventually give up gracefully."""

    def test_retry_on_500(self):
        client = _make_client()
        resp = MagicMock()
        resp.status_code = 500
        error = requests.HTTPError(response=resp)
        client.api.submit = MagicMock(side_effect=error)
        result = client.submit_file_async(b"test", "test.exe")
        # Should have retried SDK_MAX_RETRIES times
        assert client.api.submit.call_count == client.SDK_MAX_RETRIES
        assert result is None


# ── Network Drop Resilience ──────────────────────────────────────────────


class TestNetworkDropResilience:
    """Connector must handle sudden network drops."""

    def test_connection_error_on_submit(self):
        client = _make_client()
        client.api.submit = MagicMock(side_effect=ConnectionError("Connection reset"))
        result = client.submit_file_async(b"test", "test.exe")
        assert result is None

    def test_connection_error_on_poll(self):
        client = _make_client()
        client.api.lookup = MagicMock(side_effect=ConnectionError("Network unreachable"))
        result = client.get_scan_results("scan-123")
        assert result is None

    def test_os_error_on_submit(self):
        client = _make_client()
        client.api.submit = MagicMock(side_effect=OSError("Broken pipe"))
        result = client.submit_file_async(b"test", "test.exe")
        assert result is None


# ── Corrupt Response Resilience ──────────────────────────────────────────


class TestCorruptResponseResilience:
    """Connector must handle malformed API responses."""

    def test_scan_results_no_json_attr(self):
        """API returns object without .json attribute."""
        client = _make_client()
        mock_result = MagicMock()
        del mock_result.json  # Remove .json attribute
        mock_result.failed = False
        mock_result.window_closed = True
        client.api.lookup = MagicMock(return_value=mock_result)
        result = client.get_scan_results("scan-123")
        # Should handle gracefully
        assert result is None or isinstance(result, dict)

    def test_sandbox_results_no_status(self):
        """Sandbox task without .status attribute."""
        client = _make_client()
        mock_task = MagicMock()
        del mock_task.status
        client.api.sandbox_task_status = MagicMock(return_value=mock_task)
        result = client.get_sandbox_results("task-123")
        assert result is None or isinstance(result, dict)


# ── Circuit Breaker Recovery ─────────────────────────────────────────────


class TestCircuitBreakerRecovery:
    """Circuit breaker must recover after cooldown period."""

    def test_recovery_after_cooldown(self):
        cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=0)
        # Trip the breaker
        for _ in range(5):
            cb.record_failure()
        assert cb.state in ("OPEN", "HALF_OPEN")
        # Wait for cooldown (0 seconds)
        time.sleep(0.01)
        # Should transition to HALF_OPEN
        assert cb.state == "HALF_OPEN"
        assert cb.allow_request() is True
        # Success should close it
        cb.record_success()
        assert cb.state == "CLOSED"

    def test_failure_in_half_open_reopens(self):
        cb = CircuitBreaker(failure_threshold=2, cooldown_seconds=9999)
        # Trip the breaker
        cb.record_failure()
        cb.record_failure()
        assert cb.state == "OPEN"
        # Manually force HALF_OPEN by backdating opened_at
        with cb._lock:
            cb._opened_at = 0  # Expired long ago
        assert cb.state == "HALF_OPEN"
        # Another failure should re-open with fresh cooldown
        cb.record_failure()
        assert cb.state == "OPEN"

    def test_breaker_blocks_requests_when_open(self):
        cb = CircuitBreaker(failure_threshold=2, cooldown_seconds=9999)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == "OPEN"
        assert cb.allow_request() is False


# ── Actionable Error Handling ────────────────────────────────────────────


class TestActionableErrors:
    """Auth and quota errors must raise PolySwarmAPIError with actionable info."""

    def test_401_raises_with_recommendations(self):
        client = _make_client()
        resp = MagicMock()
        resp.status_code = 401
        error = requests.HTTPError(response=resp)
        client.api.submit = MagicMock(side_effect=error)
        with pytest.raises(PolySwarmAPIError) as exc_info:
            client._retry_sdk_call(client.api.submit, operation="test")
        assert "Authentication" in exc_info.value.category
        assert len(exc_info.value.recommendations) > 0

    def test_402_raises_quota_error(self):
        client = _make_client()
        resp = MagicMock()
        resp.status_code = 402
        error = requests.HTTPError(response=resp)
        client.api.submit = MagicMock(side_effect=error)
        with pytest.raises(PolySwarmAPIError) as exc_info:
            client._retry_sdk_call(client.api.submit, operation="test")
        assert "Quota" in exc_info.value.category

    def test_403_raises_access_denied(self):
        client = _make_client()
        resp = MagicMock()
        resp.status_code = 403
        error = requests.HTTPError(response=resp)
        client.api.submit = MagicMock(side_effect=error)
        with pytest.raises(PolySwarmAPIError) as exc_info:
            client._retry_sdk_call(client.api.submit, operation="test")
        assert "Access" in exc_info.value.category or "Denied" in exc_info.value.category

    def test_429_raises_rate_limit(self):
        client = _make_client()
        resp = MagicMock()
        resp.status_code = 429
        error = requests.HTTPError(response=resp)
        client.api.submit = MagicMock(side_effect=error)
        with pytest.raises(PolySwarmAPIError) as exc_info:
            client._retry_sdk_call(client.api.submit, operation="test")
        assert "Rate" in exc_info.value.category
