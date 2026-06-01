"""Unit tests for PolySwarmClient — retry logic, circuit breaker, HTTP error mapping."""

import io
import time
from unittest.mock import MagicMock, patch

import pytest
import requests
from connector.polyswarm_client import (
    CircuitBreaker,
    PolySwarmAPIError,
    PolySwarmClient,
)

# ── CircuitBreaker ──────────────────────────────────────────────────────────


class TestCircuitBreaker:
    """Verify state machine transitions: CLOSED → OPEN → HALF_OPEN → CLOSED."""

    def test_initial_state_is_closed(self):
        cb = CircuitBreaker()
        assert cb.state == CircuitBreaker.CLOSED

    def test_allows_request_when_closed(self):
        cb = CircuitBreaker()
        assert cb.allow_request() is True

    def test_opens_after_threshold_failures(self):
        cb = CircuitBreaker(failure_threshold=3, cooldown_seconds=300)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == CircuitBreaker.OPEN
        assert cb.allow_request() is False

    def test_stays_closed_below_threshold(self):
        cb = CircuitBreaker(failure_threshold=5)
        for _ in range(4):
            cb.record_failure()
        assert cb.state == CircuitBreaker.CLOSED
        assert cb.allow_request() is True

    def test_success_resets_failure_count(self):
        cb = CircuitBreaker(failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        cb.record_failure()
        cb.record_failure()
        # Only 2 consecutive failures after reset — still closed
        assert cb.state == CircuitBreaker.CLOSED

    def test_half_open_after_cooldown(self):
        cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=0.01)
        cb.record_failure()
        assert cb.state == CircuitBreaker.OPEN
        time.sleep(0.02)
        assert cb.state == CircuitBreaker.HALF_OPEN
        assert cb.allow_request() is True

    def test_success_in_half_open_closes(self):
        cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=0.01)
        cb.record_failure()
        time.sleep(0.02)
        assert cb.state == CircuitBreaker.HALF_OPEN
        cb.record_success()
        assert cb.state == CircuitBreaker.CLOSED

    def test_failure_in_half_open_reopens(self):
        cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=0.01)
        cb.record_failure()
        time.sleep(0.02)
        assert cb.state == CircuitBreaker.HALF_OPEN
        cb.record_failure()
        assert cb.state == CircuitBreaker.OPEN

    def test_reset(self):
        cb = CircuitBreaker(failure_threshold=1)
        cb.record_failure()
        assert cb.state == CircuitBreaker.OPEN
        cb.reset()
        assert cb.state == CircuitBreaker.CLOSED
        assert cb.allow_request() is True

    def test_default_threshold_is_5(self):
        cb = CircuitBreaker()
        assert cb.failure_threshold == 5

    def test_default_cooldown_is_300(self):
        cb = CircuitBreaker()
        assert cb.cooldown_seconds == 300.0


# ── PolySwarmClient retry + circuit breaker ─────────────────────────────────


class TestRetrySDKCall:
    """Verify _retry_sdk_call exponential backoff, circuit breaker integration, and BytesIO rewind."""

    @pytest.fixture
    def client(self):
        """Create a PolySwarmClient with mocked internals (no real SDK/network)."""
        with patch("connector.polyswarm_client.PolyswarmAPI"):
            c = PolySwarmClient.__new__(PolySwarmClient)
            c.helper = MagicMock()
            c.api = MagicMock()
            c._session = MagicMock()
            c._breaker = CircuitBreaker(failure_threshold=5, cooldown_seconds=300)
            return c

    def test_success_returns_result(self, client):
        func = MagicMock(return_value="result")
        assert client._retry_sdk_call(func, operation="test") == "result"
        func.assert_called_once()

    def test_success_records_on_breaker(self, client):
        func = MagicMock(return_value="ok")
        client._retry_sdk_call(func, operation="test")
        assert client._breaker.state == CircuitBreaker.CLOSED

    def test_transient_error_retries(self, client):
        func = MagicMock(side_effect=[requests.ConnectionError("fail"), "ok"])
        with patch("time.sleep"):
            result = client._retry_sdk_call(func, operation="test")
        assert result == "ok"
        assert func.call_count == 2

    def test_exhaustion_returns_none(self, client):
        func = MagicMock(side_effect=requests.ConnectionError("fail"))
        with patch("time.sleep"):
            result = client._retry_sdk_call(func, operation="test")
        assert result is None
        assert func.call_count == client.SDK_MAX_RETRIES

    def test_exhaustion_records_failure_on_breaker(self, client):
        func = MagicMock(side_effect=requests.ConnectionError("fail"))
        with patch("time.sleep"):
            client._retry_sdk_call(func, operation="test")
        assert client._breaker._failure_count == 1

    def test_circuit_open_blocks_request(self, client):
        # Force breaker open
        for _ in range(5):
            client._breaker.record_failure()
        func = MagicMock()
        result = client._retry_sdk_call(func, operation="test")
        assert result is None
        func.assert_not_called()

    def test_bytesio_args_reset_on_retry(self, client):
        bio = io.BytesIO(b"test data")
        bio.read()  # consume
        call_positions = []

        def track_position(b):
            call_positions.append(b.tell())
            raise requests.ConnectionError("fail")

        with patch("time.sleep"):
            client._retry_sdk_call(track_position, bio, operation="test")
        # Each retry should reset to 0
        assert all(pos == 0 for pos in call_positions)


# ── HTTP error mapping ──────────────────────────────────────────────────────


class TestHTTPErrorMapping:
    """Verify that actionable HTTP codes (401/402/403/429) raise PolySwarmAPIError
    while transient codes (5xx) trigger retries instead."""

    @pytest.fixture
    def client(self):
        with patch("connector.polyswarm_client.PolyswarmAPI"):
            c = PolySwarmClient.__new__(PolySwarmClient)
            c.helper = MagicMock()
            c.api = MagicMock()
            c._session = MagicMock()
            c._breaker = CircuitBreaker()
            return c

    @pytest.mark.parametrize("status_code", [401, 402, 403])
    def test_actionable_http_error_raises(self, client, status_code):
        resp = MagicMock()
        resp.status_code = status_code
        exc = requests.HTTPError(response=resp)
        func = MagicMock(side_effect=exc)
        with pytest.raises(PolySwarmAPIError) as exc_info:
            client._retry_sdk_call(func, operation="test")
        assert (
            str(status_code) in exc_info.value.detail or "HTTP" in exc_info.value.detail
        )

    def test_429_raises_rate_limit(self, client):
        resp = MagicMock()
        resp.status_code = 429
        exc = requests.HTTPError(response=resp)
        func = MagicMock(side_effect=exc)
        with pytest.raises(PolySwarmAPIError) as exc_info:
            client._retry_sdk_call(func, operation="test")
        assert "Rate Limit" in exc_info.value.category

    def test_non_actionable_http_error_retries(self, client):
        resp = MagicMock()
        resp.status_code = 500
        exc = requests.HTTPError(response=resp)
        func = MagicMock(side_effect=[exc, "recovered"])
        with patch("time.sleep"):
            result = client._retry_sdk_call(func, operation="test")
        assert result == "recovered"


# ── PolySwarmAPIError ───────────────────────────────────────────────────────


class TestPolySwarmAPIError:
    """Verify PolySwarmAPIError carries category, detail, and actionable recommendations."""

    def test_category_and_detail(self):
        err = PolySwarmAPIError("TestCat", "TestDetail")
        assert err.category == "TestCat"
        assert err.detail == "TestDetail"
        assert "TestCat" in str(err)

    def test_default_recommendations(self):
        err = PolySwarmAPIError("Cat", "Detail")
        assert len(err.recommendations) > 0

    def test_custom_recommendations(self):
        recs = ["Do this", "Do that"]
        err = PolySwarmAPIError("Cat", "Detail", recommendations=recs)
        assert err.recommendations == recs


# ── PDF generation ──────────────────────────────────────────────────────────


class TestPDFGeneration:
    """Verify generate_pdf happy path and graceful None on API failure."""

    @pytest.fixture
    def client(self):
        with patch("connector.polyswarm_client.PolyswarmAPI"):
            c = PolySwarmClient.__new__(PolySwarmClient)
            c.helper = MagicMock()
            c.api = MagicMock()
            c._session = MagicMock()
            c._breaker = CircuitBreaker()
            return c

    def test_generate_pdf_scan(self, client):
        report = MagicMock(id="report-1")
        finished = MagicMock(state="SUCCEEDED", url="https://example.com/report.pdf")
        client.api.report_create = MagicMock(return_value=report)
        client.api.report_wait_for = MagicMock(return_value=finished)
        client._session.get.return_value = MagicMock(
            status_code=200, content=b"PDF-DATA"
        )

        result = client.generate_pdf("scan-123", "scan")
        assert result == b"PDF-DATA"

    def test_generate_pdf_returns_none_on_failure(self, client):
        client.api.report_create = MagicMock(return_value=None)
        result = client.generate_pdf("scan-123", "scan")
        assert result is None


# ── LLM report ──────────────────────────────────────────────────────────────


class TestLLMReport:
    """Verify create/collect LLM report lifecycle, including guard for missing IDs."""

    @pytest.fixture
    def client(self):
        with patch("connector.polyswarm_client.PolyswarmAPI"):
            c = PolySwarmClient.__new__(PolySwarmClient)
            c.helper = MagicMock()
            c.api = MagicMock()
            c._session = MagicMock()
            c._breaker = CircuitBreaker()
            return c

    def test_create_llm_report_returns_task_id(self, client):
        task = MagicMock(id="llm-task-1", state="PENDING")
        client.api.llm_report_create = MagicMock(return_value=task)
        result = client.create_llm_report(instance_id="scan-123")
        assert result == "llm-task-1"

    def test_create_llm_report_no_ids_returns_none(self, client):
        result = client.create_llm_report()
        assert result is None

    def test_create_llm_report_maps_sandbox_task_id_to_cape(self, client):
        # The SDK accepts cape_/triage_sandbox_task_id, NOT a generic
        # sandbox_task_id. fake_sdk carries the real signature, so forwarding
        # the wrong kwarg would TypeError (swallowed -> None) and fail this.
        captured = {}

        def fake_sdk(
            instance_id=None, cape_sandbox_task_id=None, triage_sandbox_task_id=None
        ):
            captured["cape"] = cape_sandbox_task_id
            captured["triage"] = triage_sandbox_task_id
            return MagicMock(id="llm-cape", state="PENDING")

        client.api.llm_report_create = fake_sdk
        result = client.create_llm_report(sandbox_task_id="sb-9", provider="cape")
        assert result == "llm-cape"
        assert captured == {"cape": "sb-9", "triage": None}

    def test_create_llm_report_maps_sandbox_task_id_to_triage(self, client):
        captured = {}

        def fake_sdk(
            instance_id=None, cape_sandbox_task_id=None, triage_sandbox_task_id=None
        ):
            captured["cape"] = cape_sandbox_task_id
            captured["triage"] = triage_sandbox_task_id
            return MagicMock(id="llm-triage", state="PENDING")

        client.api.llm_report_create = fake_sdk
        result = client.create_llm_report(sandbox_task_id="sb-7", provider="triage")
        assert result == "llm-triage"
        assert captured == {"cape": None, "triage": "sb-7"}

    def test_sdk_llm_report_create_signature_contract(self):
        """Guard the real SDK signature create_llm_report depends on.

        The mapping tests above use a fake with the expected signature; a
        MagicMock would accept any kwarg and hide a drift. This introspects
        the installed SDK to confirm it really exposes the provider-specific
        kwargs and has no generic ``sandbox_task_id``. If the SDK ever renames
        or drops these, fix the mapping in ``create_llm_report``.
        """
        import inspect

        from connector.polyswarm import PolyswarmAPI

        params = inspect.signature(PolyswarmAPI.llm_report_create).parameters
        assert "instance_id" in params
        assert "cape_sandbox_task_id" in params
        assert "triage_sandbox_task_id" in params
        assert "sandbox_task_id" not in params

    def test_collect_llm_report_success(self, client):
        task = MagicMock(state="SUCCEEDED", url="https://example.com/llm.txt")
        client.api.llm_report_get = MagicMock(return_value=task)
        client._session.get.return_value = MagicMock(
            status_code=200, text="LLM analysis..."
        )

        result = client.collect_llm_report("llm-task-1", timeout=5, poll_interval=0.01)
        assert result == "LLM analysis..."

    def test_collect_llm_report_empty_id_returns_none(self, client):
        assert client.collect_llm_report("") is None
        assert client.collect_llm_report(None) is None
