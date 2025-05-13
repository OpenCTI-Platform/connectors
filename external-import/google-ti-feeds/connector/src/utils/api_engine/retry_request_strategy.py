"""Base retry request strategy with hooks handling."""

import asyncio
from typing import Any, Optional

from .api_request_model import ApiRequestModel
from .exceptions.api_circuit_open_error import ApiCircuitOpenError
from .exceptions.api_error import ApiError
from .exceptions.api_http_error import ApiHttpError
from .exceptions.api_ratelimit_error import ApiRateLimitError
from .exceptions.api_timeout_error import ApiTimeoutError
from .exceptions.api_validation_error import ApiValidationError
from .interfaces.base_circuit_breaker import BaseCircuitBreaker
from .interfaces.base_http_client import BaseHttpClient
from .interfaces.base_rate_limiter import BaseRateLimiter
from .interfaces.base_request_hook import BaseRequestHook
from .interfaces.base_request_model import BaseRequestModel
from .interfaces.base_request_strategy import BaseRequestStrategy


class RetryRequestStrategy(BaseRequestStrategy):
    """Strategy that retries failed requests intelligently."""

    def __init__(
        self,
        http: BaseHttpClient,
        breaker: BaseCircuitBreaker,
        limiter: Optional[BaseRateLimiter] = None,
        hooks: Optional[list[BaseRequestHook]] = None,
        max_retries: int = 5,
        backoff: int = 2,
    ) -> None:
        """Initialize the retry request strategy.

        Args:
            http: The HTTP client to use.
            breaker: The circuit breaker to use.
            limiter: The rate limiter to use.
            hooks: The request hooks to use.
            max_retries: The maximum number of retries.
            backoff: The backoff factor.

        Raises:
                Valueor: If max_retries is less than 0.
                ValueError: If backoff is less than 1.

        """
        self.http = http
        self.breaker = breaker
        self.limiter = limiter
        self.hooks = hooks or []
        self.max_retries = max_retries
        self.backoff = backoff

    async def _perform_single_attempt(self, request: BaseRequestModel) -> Any:
        """Perform a single request attempt and process response."""
        try:
            if self.limiter:
                await self.limiter.acquire()

            for hook in self.hooks:
                await hook.before(request)
            if not isinstance(request, ApiRequestModel):
                raise TypeError("RetryRequestStrategy only supports ApiRequestModel")
            api_req: ApiRequestModel = request

            raw = await self.http.request(
                api_req.method,
                api_req.url,
                headers=api_req.headers,
                params=api_req.params,
                json_payload=api_req.json_payload,
                timeout=api_req.timeout,
            )

            for hook in self.hooks:
                await hook.after(request, raw)

            data = raw.get(request.response_key) if request.response_key else raw

            if request.model:
                try:
                    return request.model.model_validate(data)
                except Exception as validation_err:
                    raise ApiValidationError(
                        f"Response validation failed: {str(validation_err)}"
                    ) from validation_err
            return data
        except (
            ApiTimeoutError,
            ApiRateLimitError,
            ApiHttpError,
            ApiValidationError,
        ) as known_api_err:
            raise known_api_err
        except ApiError as other_api_err:
            raise other_api_err
        except Exception as generic_err:
            raise ApiError(
                f"An unexpected error occurred during request processing: {str(generic_err)}"
            ) from generic_err

    async def execute(self, request: BaseRequestModel) -> Any:
        """Execute the request with retry and rate limiting.

        Args:
            request: The request to execute.

        Returns:
            The response from the request.

        Raises:
            ApiCircuitOpenError: If the circuit breaker is open.
            ApiRateLimitExceededError: If the rate limit is exceeded.
            ApiError: If the request fails.

        """
        if self.breaker.is_open():
            raise ApiCircuitOpenError("Circuit breaker is open")

        current_backoff_delay = self.backoff
        last_exception: Optional[Exception] = None

        for attempt in range(self.max_retries + 1):
            try:
                return await self._perform_single_attempt(request)
            except (ApiTimeoutError, ApiRateLimitError, ApiHttpError) as e:
                self.breaker.record_failure()
                last_exception = e
                if isinstance(e, ApiHttpError) and e.status_code < 500:
                    raise

                if attempt == self.max_retries:
                    raise

                await asyncio.sleep(current_backoff_delay)
                current_backoff_delay *= 2
            except ApiError as e:
                raise e

        if last_exception:
            raise last_exception
        raise ApiError("Max retries exceeded without a successful response.")
