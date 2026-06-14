"""RED tests for Feature: Resilient Request Orchestration.

Tests that ApiClient / RetryRequestStrategy compose HTTP client, circuit
breaker, rate limiter, and hooks into a resilient request pipeline.

All tests MUST fail with ImportError until the implementation exists.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest
from google_secops_siem_incidents.utils.api_engine.aio_http_client import AioHttpClient
from google_secops_siem_incidents.utils.api_engine.api_request_model import (
    ApiRequestModel,
)
from google_secops_siem_incidents.utils.api_engine.circuit_breaker import CircuitBreaker
from google_secops_siem_incidents.utils.api_engine.exceptions import (
    ApiCircuitOpenError,
    ApiError,
    ApiHttpError,
    ApiValidationError,
)
from google_secops_siem_incidents.utils.api_engine.interfaces.base_request_hook import (
    BaseRequestHook,
)
from google_secops_siem_incidents.utils.api_engine.rate_limiter import (
    RateLimiterRegistry,
    TokenBucketRateLimiter,
)
from google_secops_siem_incidents.utils.api_engine.retry_request_strategy import (
    RetryRequestStrategy,
)


# ---------------------------------------------------------------------------
# Fixture: clean registry
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def clear_registry():
    RateLimiterRegistry.clear()
    yield
    RateLimiterRegistry.clear()


# ---------------------------------------------------------------------------
# Scenario: Successful request returns the response body
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_successful_request_returns_response_body():
    """call_api() on a reachable endpoint returns the raw response body."""

    async def _given_strategy_with_mock_http_client():
        http_client = AsyncMock(spec=AioHttpClient)
        http_client.request = AsyncMock(return_value={"result": "ok"})
        cb = MagicMock(spec=CircuitBreaker)
        cb.is_open = MagicMock(return_value=False)
        strategy = RetryRequestStrategy(
            http_client=http_client,
            circuit_breaker=cb,
            max_retries=3,
            backoff=2,
        )
        return strategy, http_client

    async def _when_api_request_made(strategy):
        request = MagicMock(spec=ApiRequestModel)
        request.method = "GET"
        request.url = "https://example.com/api"
        request.headers = {}
        request.params = {}
        request.json_body = None
        request.data = None
        request.timeout = None
        request.response_key = None
        request.response_model = None
        return await strategy.execute(request)

    def _then_raw_response_body_returned(response):
        assert response == {"result": "ok"}

    strategy, _ = await _given_strategy_with_mock_http_client()
    response = await _when_api_request_made(strategy)
    _then_raw_response_body_returned(response)


# ---------------------------------------------------------------------------
# Scenario: Transient server error is retried up to the limit
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_transient_server_error_retried_up_to_limit():
    """500 errors are retried; success on 3rd attempt is returned."""

    async def _given_server_fails_twice_then_succeeds():
        http_client = AsyncMock(spec=AioHttpClient)
        http_client.request = AsyncMock(
            side_effect=[
                ApiHttpError("Server Error", status_code=500),
                ApiHttpError("Server Error", status_code=500),
                {"result": "recovered"},
            ]
        )
        cb = MagicMock(spec=CircuitBreaker)
        cb.is_open = MagicMock(return_value=False)
        strategy = RetryRequestStrategy(
            http_client=http_client,
            circuit_breaker=cb,
            max_retries=3,
            backoff=0,
        )
        return strategy, http_client

    async def _when_api_request_made(strategy):
        request = MagicMock(spec=ApiRequestModel)
        request.method = "GET"
        request.url = "https://example.com/api"
        request.headers = {}
        request.params = {}
        request.json_body = None
        request.data = None
        request.timeout = None
        request.response_key = None
        request.response_model = None
        return await strategy.execute(request)

    def _then_successful_response_returned(response):
        assert response == {"result": "recovered"}

    strategy, http_client = await _given_server_fails_twice_then_succeeds()
    response = await _when_api_request_made(strategy)
    _then_successful_response_returned(response)


# ---------------------------------------------------------------------------
# Scenario: Non-retryable client error propagates immediately without retry
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_non_retryable_client_error_propagates_immediately():
    """400 error is raised immediately, no retries."""

    async def _given_server_responds_400():
        http_client = AsyncMock(spec=AioHttpClient)
        http_client.request = AsyncMock(
            side_effect=ApiHttpError("Bad Request", status_code=400)
        )
        cb = MagicMock(spec=CircuitBreaker)
        cb.is_open = MagicMock(return_value=False)
        strategy = RetryRequestStrategy(
            http_client=http_client,
            circuit_breaker=cb,
            max_retries=3,
            backoff=0,
        )
        return strategy, http_client

    async def _when_api_request_made(strategy):
        request = MagicMock(spec=ApiRequestModel)
        request.method = "GET"
        request.url = "https://example.com/api"
        request.headers = {}
        request.params = {}
        request.json_body = None
        request.data = None
        request.timeout = None
        request.response_key = None
        request.response_model = None
        return await strategy.execute(request)

    def _then_http_error_400_raised_immediately(exc_info, http_client):
        assert exc_info.value.status_code == 400
        assert http_client.request.call_count == 1

    strategy, http_client = await _given_server_responds_400()
    with pytest.raises(ApiHttpError) as exc_info:
        await _when_api_request_made(strategy)
    _then_http_error_400_raised_immediately(exc_info, http_client)


# ---------------------------------------------------------------------------
# Scenario: Open circuit rejects the request before it is sent
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_open_circuit_rejects_request_before_send():
    """Open circuit raises ApiCircuitOpenError without HTTP call."""

    async def _given_open_circuit_breaker():
        http_client = AsyncMock(spec=AioHttpClient)
        cb = MagicMock(spec=CircuitBreaker)
        cb.is_open = MagicMock(return_value=True)
        strategy = RetryRequestStrategy(
            http_client=http_client,
            circuit_breaker=cb,
            max_retries=3,
            backoff=0,
        )
        return strategy, http_client

    async def _when_api_request_made(strategy):
        request = MagicMock(spec=ApiRequestModel)
        request.method = "GET"
        request.url = "https://example.com/api"
        request.headers = {}
        request.params = {}
        request.json_body = None
        request.data = None
        request.timeout = None
        request.response_key = None
        request.response_model = None
        return await strategy.execute(request)

    def _then_circuit_open_error_raised_no_http(http_client):
        http_client.request.assert_not_called()

    strategy, http_client = await _given_open_circuit_breaker()
    with pytest.raises(ApiCircuitOpenError):
        await _when_api_request_made(strategy)
    _then_circuit_open_error_raised_no_http(http_client)


# ---------------------------------------------------------------------------
# Scenario: Rate limit slot is acquired before each request attempt
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_rate_limit_slot_acquired_before_request():
    """When a rate limiter is configured, acquire() is called before request."""

    async def _given_strategy_with_rate_limiter():
        http_client = AsyncMock(spec=AioHttpClient)
        http_client.request = AsyncMock(return_value={"ok": True})
        cb = MagicMock(spec=CircuitBreaker)
        cb.is_open = MagicMock(return_value=False)
        limiter = AsyncMock(spec=TokenBucketRateLimiter)
        limiter.acquire = AsyncMock()
        strategy = RetryRequestStrategy(
            http_client=http_client,
            circuit_breaker=cb,
            max_retries=3,
            backoff=0,
            rate_limiter=limiter,
        )
        return strategy, limiter

    async def _when_api_request_made(strategy):
        request = MagicMock(spec=ApiRequestModel)
        request.method = "GET"
        request.url = "https://example.com/api"
        request.headers = {}
        request.params = {}
        request.json_body = None
        request.data = None
        request.timeout = None
        request.response_key = None
        request.response_model = None
        return await strategy.execute(request)

    def _then_rate_limiter_acquired(limiter):
        limiter.acquire.assert_called()

    strategy, limiter = await _given_strategy_with_rate_limiter()
    await _when_api_request_made(strategy)
    _then_rate_limiter_acquired(limiter)


# ---------------------------------------------------------------------------
# Scenario: Registered hooks are called around the request
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_registered_hooks_called_around_request():
    """before() is called before, after() is called after the request."""

    async def _given_strategy_with_hook():
        http_client = AsyncMock(spec=AioHttpClient)
        http_client.request = AsyncMock(return_value={"ok": True})
        cb = MagicMock(spec=CircuitBreaker)
        cb.is_open = MagicMock(return_value=False)
        hook = MagicMock(spec=BaseRequestHook)
        hook.before = AsyncMock()
        hook.after = AsyncMock()
        strategy = RetryRequestStrategy(
            http_client=http_client,
            circuit_breaker=cb,
            max_retries=3,
            backoff=0,
            hooks=[hook],
        )
        return strategy, hook

    async def _when_api_request_made(strategy):
        request = MagicMock(spec=ApiRequestModel)
        request.method = "GET"
        request.url = "https://example.com/api"
        request.headers = {}
        request.params = {}
        request.json_body = None
        request.data = None
        request.timeout = None
        request.response_key = None
        request.response_model = None
        return await strategy.execute(request)

    def _then_before_hook_called(hook):
        hook.before.assert_called_once()

    def _then_after_hook_called(hook):
        hook.after.assert_called_once()

    strategy, hook = await _given_strategy_with_hook()
    await _when_api_request_made(strategy)
    _then_before_hook_called(hook)
    _then_after_hook_called(hook)


# ---------------------------------------------------------------------------
# Scenario: Specific response field is extracted when field name is configured
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_response_field_extracted_when_configured():
    """response_key='data' returns only the 'data' portion."""

    async def _given_server_returns_nested_response():
        http_client = AsyncMock(spec=AioHttpClient)
        http_client.request = AsyncMock(return_value={"data": {"id": 1}, "meta": {}})
        cb = MagicMock(spec=CircuitBreaker)
        cb.is_open = MagicMock(return_value=False)
        strategy = RetryRequestStrategy(
            http_client=http_client,
            circuit_breaker=cb,
            max_retries=3,
            backoff=0,
        )
        return strategy

    async def _when_request_configured_with_response_key(strategy):
        request = MagicMock(spec=ApiRequestModel)
        request.method = "GET"
        request.url = "https://example.com/api"
        request.headers = {}
        request.params = {}
        request.json_body = None
        request.data = None
        request.timeout = None
        request.response_key = "data"
        request.response_model = None
        return await strategy.execute(request)

    def _then_only_data_portion_returned(response):
        assert response == {"id": 1}

    strategy = await _given_server_returns_nested_response()
    response = await _when_request_configured_with_response_key(strategy)
    _then_only_data_portion_returned(response)


# ---------------------------------------------------------------------------
# Scenario: Response is validated against the configured shape
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_response_validated_against_configured_shape():
    """Response validated via response_model returns a model instance."""
    from pydantic import BaseModel

    class ResponseShape(BaseModel):
        id: int
        name: str

    async def _given_server_returns_matching_response():
        http_client = AsyncMock(spec=AioHttpClient)
        http_client.request = AsyncMock(return_value={"id": 1, "name": "test"})
        cb = MagicMock(spec=CircuitBreaker)
        cb.is_open = MagicMock(return_value=False)
        strategy = RetryRequestStrategy(
            http_client=http_client,
            circuit_breaker=cb,
            max_retries=3,
            backoff=0,
        )
        return strategy

    async def _when_request_configured_with_response_shape(strategy):
        request = MagicMock(spec=ApiRequestModel)
        request.method = "GET"
        request.url = "https://example.com/api"
        request.headers = {}
        request.params = {}
        request.json_body = None
        request.data = None
        request.timeout = None
        request.response_key = None
        request.response_model = ResponseShape
        return await strategy.execute(request)

    def _then_response_is_validated_instance(response):
        assert isinstance(response, ResponseShape)
        assert response.id == 1
        assert response.name == "test"

    strategy = await _given_server_returns_matching_response()
    response = await _when_request_configured_with_response_shape(strategy)
    _then_response_is_validated_instance(response)


# ---------------------------------------------------------------------------
# Scenario: Missing response field raises a validation error
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_missing_response_field_raises_validation_error():
    """Missing response_key in response dict raises ApiValidationError (not KeyError)."""

    async def _given_server_returns_wrong_keys():
        http_client = AsyncMock(spec=AioHttpClient)
        http_client.request = AsyncMock(return_value={"other_key": {}})
        cb = MagicMock(spec=CircuitBreaker)
        cb.is_open = MagicMock(return_value=False)
        strategy = RetryRequestStrategy(
            http_client=http_client,
            circuit_breaker=cb,
            max_retries=3,
            backoff=0,
        )
        return strategy

    async def _when_request_extracts_missing_field(strategy):
        request = MagicMock(spec=ApiRequestModel)
        request.method = "GET"
        request.url = "https://example.com/api"
        request.headers = {}
        request.params = {}
        request.json_body = None
        request.data = None
        request.timeout = None
        request.response_key = "data"
        request.response_model = None
        return await strategy.execute(request)

    def _then_validation_error_raised():
        pass  # assertion via pytest.raises

    strategy = await _given_server_returns_wrong_keys()
    with pytest.raises(ApiValidationError):
        await _when_request_extracts_missing_field(strategy)
    _then_validation_error_raised()


# ---------------------------------------------------------------------------
# Design constraint: retry loop limits attempts correctly
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_retry_loop_limits_attempts_to_max_retries():
    """With max_retries=3, exactly 3 attempts are made (not more)."""

    async def _given_server_always_fails_500():
        http_client = AsyncMock(spec=AioHttpClient)
        http_client.request = AsyncMock(
            side_effect=ApiHttpError("Server Error", status_code=500)
        )
        cb = MagicMock(spec=CircuitBreaker)
        cb.is_open = MagicMock(return_value=False)
        strategy = RetryRequestStrategy(
            http_client=http_client,
            circuit_breaker=cb,
            max_retries=3,
            backoff=0,
        )
        return strategy, http_client

    async def _when_api_request_made(strategy):
        request = MagicMock(spec=ApiRequestModel)
        request.method = "GET"
        request.url = "https://example.com/api"
        request.headers = {}
        request.params = {}
        request.json_body = None
        request.data = None
        request.timeout = None
        request.response_key = None
        request.response_model = None
        with pytest.raises(ApiHttpError):
            await strategy.execute(request)

    def _then_exactly_max_retries_attempts_made(http_client):
        assert http_client.request.call_count == 3

    strategy, http_client = await _given_server_always_fails_500()
    await _when_api_request_made(strategy)
    _then_exactly_max_retries_attempts_made(http_client)


# ---------------------------------------------------------------------------
# Scenario: Validation errors fail fast and are not retried
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_validation_error_is_not_retried():
    """A deterministic parse/validation failure is raised on the first attempt."""

    async def _given_server_always_returns_wrong_keys():
        http_client = AsyncMock(spec=AioHttpClient)
        http_client.request = AsyncMock(return_value={"other_key": {}})
        cb = MagicMock(spec=CircuitBreaker)
        cb.is_open = MagicMock(return_value=False)
        strategy = RetryRequestStrategy(
            http_client=http_client,
            circuit_breaker=cb,
            max_retries=3,
            backoff=0,
        )
        return strategy, http_client

    async def _when_request_extracts_missing_field(strategy):
        request = MagicMock(spec=ApiRequestModel)
        request.method = "GET"
        request.url = "https://example.com/api"
        request.headers = {}
        request.params = {}
        request.json_body = None
        request.data = None
        request.timeout = None
        request.response_key = "data"
        request.response_model = None
        return await strategy.execute(request)

    def _then_request_made_once_without_retry(http_client):
        assert http_client.request.call_count == 1

    strategy, http_client = await _given_server_always_returns_wrong_keys()
    with pytest.raises(ApiValidationError):
        await _when_request_extracts_missing_field(strategy)
    _then_request_made_once_without_retry(http_client)


# ---------------------------------------------------------------------------
# Scenario: After-hook failures surface as ApiError, never a raw exception
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_after_hook_exception_wrapped_as_api_error():
    """A raw exception raised by an after-hook is wrapped in ApiError."""

    async def _given_strategy_with_failing_after_hook():
        http_client = AsyncMock(spec=AioHttpClient)
        http_client.request = AsyncMock(return_value={"ok": True})
        cb = MagicMock(spec=CircuitBreaker)
        cb.is_open = MagicMock(return_value=False)
        hook = MagicMock(spec=BaseRequestHook)
        hook.before = AsyncMock()
        hook.after = AsyncMock(side_effect=RuntimeError("hook boom"))
        strategy = RetryRequestStrategy(
            http_client=http_client,
            circuit_breaker=cb,
            max_retries=1,
            backoff=0,
            hooks=[hook],
        )
        return strategy

    async def _when_api_request_made(strategy):
        request = MagicMock(spec=ApiRequestModel)
        request.method = "GET"
        request.url = "https://example.com/api"
        request.headers = {}
        request.params = {}
        request.json_body = None
        request.data = None
        request.timeout = None
        request.response_key = None
        request.response_model = None
        return await strategy.execute(request)

    strategy = await _given_strategy_with_failing_after_hook()
    with pytest.raises(ApiError) as exc_info:
        await _when_api_request_made(strategy)
    assert "hook boom" in str(exc_info.value)
