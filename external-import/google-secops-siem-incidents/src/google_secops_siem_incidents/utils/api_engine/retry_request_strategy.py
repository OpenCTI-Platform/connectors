"""Retry-capable request strategy with circuit breaker and rate limiter support."""

import asyncio
import logging
from typing import Any

from pydantic import BaseModel, ValidationError

from .api_request_model import ApiRequestModel
from .exceptions import (
    ApiCircuitOpenError,
    ApiError,
    ApiHttpError,
    ApiRateLimitError,
    ApiTimeoutError,
    ApiValidationError,
)
from .interfaces.base_circuit_breaker import BaseCircuitBreaker
from .interfaces.base_http_client import BaseHttpClient
from .interfaces.base_rate_limiter import BaseRateLimiter
from .interfaces.base_request_hook import BaseRequestHook
from .interfaces.base_request_model import BaseRequestModel
from .interfaces.base_request_strategy import BaseRequestStrategy
from .rate_limiter import RateLimiterRegistry


class RetryRequestStrategy(BaseRequestStrategy):
    """Executes requests with retry, circuit breaker, rate limiting, and hooks."""

    def __init__(
        self,
        http_client: BaseHttpClient,
        circuit_breaker: BaseCircuitBreaker,
        max_retries: int = 3,
        backoff: float = 2.0,
        rate_limiter: dict[str, Any] | BaseRateLimiter | None = None,
        hooks: list[BaseRequestHook] | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        """Initialise with HTTP client, circuit breaker, and retry settings.

        Args:
            http_client: Underlying async HTTP client.
            circuit_breaker: Circuit breaker to track failure state.
            max_retries: Maximum number of retry attempts.
            backoff: Base backoff multiplier in seconds between retries.
            rate_limiter: Rate limiter instance or registry config dict.
            hooks: Optional list of request lifecycle hooks.
            logger: Optional logger; defaults to module logger.
        """
        self._http = http_client
        self._breaker = circuit_breaker
        self._max_retries = max_retries
        self._backoff = backoff
        self._limiter_config = rate_limiter
        self._hooks = hooks or []
        self._logger = logger or logging.getLogger(__name__)

    def _get_rate_limiter(self) -> BaseRateLimiter | None:
        """Resolve and return the configured rate limiter, if any.

        Returns:
            Configured BaseRateLimiter instance, or None.
        """
        if self._limiter_config is None:
            return None
        if isinstance(self._limiter_config, BaseRateLimiter):
            return self._limiter_config
        cfg = self._limiter_config
        try:
            key = cfg["key"]
            max_requests = cfg["max_requests"]
            period = cfg["period"]
        except KeyError as exc:
            raise ApiValidationError(
                f"Invalid rate_limiter config: missing key {exc.args[0]!r}"
            ) from exc

        return RateLimiterRegistry.get_or_create(
            key=key,
            max_requests=max_requests,
            period=period,
        )

    def _parse_response(
        self,
        response: dict[str, Any],
        response_key: str | None,
        response_model: type[BaseModel] | None,
    ) -> Any:
        """Extract and optionally validate the response payload.

        Args:
            response: Raw response dict from the HTTP client.
            response_key: Key to extract from the dict, or None for the full dict.
            response_model: Pydantic model to validate against, or None.

        Returns:
            Validated model instance, extracted sub-dict, or raw dict.

        Raises:
            ApiValidationError: If response_key is missing or model validation fails.
        """
        data: Any = response
        if response_key is not None:
            if response_key not in response:
                raise ApiValidationError(
                    f"Response key '{response_key}' not found in response"
                )
            data = response[response_key]
        if response_model is not None:
            try:
                return response_model.model_validate(data)
            except (ValidationError, Exception) as exc:
                raise ApiValidationError(str(exc)) from exc
        return data

    async def _handle_attempt_error(
        self,
        exc: ApiError,
        attempts: int,
        url: str,
    ) -> None:
        """Record failure and sleep for backoff; raise if retries exhausted.

        Args:
            exc: The API error that occurred.
            attempts: Current attempt count.
            url: Request URL (for logging).

        Raises:
            ApiError: Re-raised when all retries are exhausted.
        """
        self._breaker.record_failure()
        if attempts >= self._max_retries:
            self._logger.error(
                "All %d retries exhausted for %s: %s",
                self._max_retries,
                url,
                exc,
            )
            raise exc
        self._logger.warning(
            "Request failed (attempt %d/%d), retrying in %.1fs: %s",
            attempts,
            self._max_retries,
            self._backoff * attempts,
            exc,
        )
        await asyncio.sleep(self._backoff * attempts)

    def _check_circuit(self, url: str) -> None:
        """Raise if the circuit breaker is open.

        Args:
            url: Request URL (for logging).

        Raises:
            ApiCircuitOpenError: If the circuit breaker is currently open.
        """
        if self._breaker.is_open():
            self._logger.warning(
                "Circuit breaker is open — request blocked for %s", url
            )
            raise ApiCircuitOpenError("Circuit is open — request blocked")

    async def _pre_request(
        self,
        request: ApiRequestModel,
        limiter: BaseRateLimiter | None,
    ) -> None:
        """Run rate limiting and before-hooks ahead of the HTTP call.

        Args:
            request: The request model about to be sent.
            limiter: Active rate limiter, or None.
        """
        if limiter is not None:
            await limiter.acquire()
        for hook in self._hooks:
            try:
                await hook.before(request)
            except Exception as exc:
                raise ApiError(str(exc)) from exc

    async def execute(self, request: BaseRequestModel) -> Any:
        """Execute the request with retries, circuit breaking, and rate limiting.

        Args:
            request: The request model to execute.

        Returns:
            Parsed response, validated against response_model if provided.

        Raises:
            TypeError: If request is not an ApiRequestModel.
            ApiCircuitOpenError: If the circuit breaker is open.
            ApiError: On exhausted retries or non-retryable HTTP errors.
        """
        if not isinstance(request, ApiRequestModel):
            raise TypeError(f"Expected ApiRequestModel, got {type(request)}")

        limiter = self._get_rate_limiter()
        attempts = 0

        while attempts < self._max_retries:
            attempts += 1
            self._check_circuit(request.url)
            await self._pre_request(request, limiter)

            try:
                response = await self._http.request(
                    method=request.method,
                    url=request.url,
                    headers=request.headers,
                    params=request.params,
                    data=request.data,
                    json_payload=request.json_body,
                    timeout=request.timeout,
                )
                self._breaker.reset()

                for hook in self._hooks:
                    try:
                        await hook.after(request, response)
                    except Exception as exc:
                        # Keep the api_engine contract: callers only ever see
                        # ApiError subclasses, never raw hook exceptions
                        # (mirrors the before-hook handling in _pre_request).
                        raise ApiError(str(exc)) from exc

                return self._parse_response(
                    response,
                    request.response_key,
                    request.response_model,
                )

            except ApiCircuitOpenError:
                raise

            except ApiValidationError:
                # Parse/validation failures are deterministic: the same response
                # would fail identically on every retry, so fail fast instead of
                # burning the retry budget.
                raise

            except ApiHttpError as exc:
                if 400 <= exc.status_code < 500 and exc.status_code != 429:
                    raise  # non-retryable 4xx (not 429)
                await self._handle_attempt_error(exc, attempts, request.url)

            except (ApiTimeoutError, ApiRateLimitError, ApiError) as exc:
                await self._handle_attempt_error(exc, attempts, request.url)

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._http.close()
