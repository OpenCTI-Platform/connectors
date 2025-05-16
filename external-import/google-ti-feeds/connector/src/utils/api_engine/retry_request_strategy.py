"""Base retry request strategy with hooks handling."""

import asyncio
import logging
from typing import TYPE_CHECKING, Any, Dict, Optional, Union

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
from .rate_limiter import RateLimiterRegistry

if TYPE_CHECKING:
    from logging import Logger


class RetryRequestStrategy(BaseRequestStrategy):
    """Strategy that retries failed requests intelligently."""

    def __init__(
        self,
        http: BaseHttpClient,
        breaker: BaseCircuitBreaker,
        limiter: Optional[Union[BaseRateLimiter, Dict[str, Any]]] = None,
        hooks: Optional[list[BaseRequestHook]] = None,
        max_retries: int = 5,
        backoff: int = 2,
        logger: Optional["Logger"] = None,
    ) -> None:
        """Initialize the retry request strategy.

        Args:
            http: The HTTP client to use.
            breaker: The circuit breaker to use.
            limiter: The rate limiter to use or a dictionary of rate limiter configuration.
                if a dictionary is provided, it will be used to initialize the rate limiter with the following keys:
                   - key: The rate limiter key.
                   - max_requests: The maximum number of requests allowed within the time window.
                   - period: The time window in seconds.
            hooks: The request hooks to use.
            max_retries: The maximum number of retries.
            backoff: The backoff factor.
            logger: The logger to use.

        Raises:
                Valueor: If max_retries is less than 0.
                ValueError: If backoff is less than 1.

        """
        self.http = http
        self.breaker = breaker
        self.hooks = hooks or []
        self.max_retries = max_retries
        self.backoff = backoff
        self._logger = logger or logging.getLogger(__name__)

        self._limiter_config = None
        self.limiter = None

        if isinstance(limiter, dict):
            self._limiter_config = limiter
        else:
            self.limiter = limiter
        self._initialized = False

    async def _initialize(self) -> None:
        """Initialize the retry strategy."""
        if self._initialized:
            return

        if self._limiter_config and not self.limiter:
            required_keys = ["key", "max_requests", "period"]
            if not all(key in self._limiter_config for key in required_keys):
                missing_keys = [
                    key for key in required_keys if key not in self._limiter_config
                ]
                self._logger.warning(
                    f"Missing required keys in limiter config: {missing_keys}"
                )
                raise ValueError(
                    f"Missing required keys in limiter config: {missing_keys}"
                )

            self.limiter = await RateLimiterRegistry.get(
                key=self._limiter_config["key"],
                max_requests=self._limiter_config["max_requests"],
                period=self._limiter_config["period"],
            )
            self._logger.debug(
                f"Rate limiter initialized with key {self._limiter_config['key']}",
                f"max_requests={self._limiter_config['max_requests']}, period={self._limiter_config['period']}",
            )

        self._initialized = True

    async def _perform_single_attempt(self, request: BaseRequestModel) -> Any:
        """Perform a single request attempt and process response."""
        try:
            await self._initialize()

            if self.limiter:
                await self.limiter.acquire()
                self._logger.debug(
                    f"Rate limiter token acquired for {self.api_req.url}"
                )

            for hook in self.hooks:
                await hook.before(self.api_req)

            self._logger.debug(
                f"Attempting {self.api_req.method} to {self.api_req.url} (Headers: {self.api_req.headers is not None}, "
                f"Params: {self.api_req.params is not None}, JSON: {self.api_req.json_payload is not None})"
            )

            raw = await self.http.request(
                self.api_req.method,
                self.api_req.url,
                headers=self.api_req.headers,
                params=self.api_req.params,
                json_payload=self.api_req.json_payload,
                timeout=self.api_req.timeout,
            )
            self._logger.debug(f"Raw response received from {self.api_req.url}")

            for hook in self.hooks:
                await hook.after(self.api_req, raw)

            data = (
                raw.get(self.api_req.response_key) if self.api_req.response_key else raw
            )

            if self.api_req.model:
                try:
                    return self.api_req.model.model_validate(data)
                except Exception as validation_err:
                    self._logger.error(  # type: ignore[call-arg]
                        f"Response validation failed: {validation_err}",
                        meta={"error": str(validation_err)},
                    )
                    raise ApiValidationError(
                        f"Response validation failed: {str(validation_err)}"
                    ) from validation_err
            self._logger.debug(f"Successfully processed request to {self.api_req.url}")
            return data
        except (
            ApiTimeoutError,
            ApiRateLimitError,
            ApiHttpError,
            ApiValidationError,
            ApiCircuitOpenError,
        ) as known_api_err:
            self._logger.warning(
                f"Known API error during attempt for {self.api_req.url}: {type(known_api_err).__name__} - {known_api_err}"
            )
            raise known_api_err
        except ApiError as other_api_err:
            self._logger.warning(
                f"API error during attempt for {self.api_req.url}: {other_api_err}"
            )
            raise other_api_err
        except Exception as generic_err:
            self._logger.error(  # type: ignore[call-arg]
                f"Unexpected error during single attempt for {self.api_req.url}",
                meta={"error": str(generic_err)},
            )
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
        if not isinstance(request, ApiRequestModel):
            self._logger.error(
                "RetryRequestStrategy only supports ApiRequestModel",  # type: ignore[call-arg]
                meta={"error": "RetryRequestStrategy only supports ApiRequestModel"},
            )
            raise TypeError("RetryRequestStrategy only supports ApiRequestModel")

        self.api_req: ApiRequestModel = request

        if self.breaker.is_open():
            self._logger.warning(
                f"[API Client] Circuit breaker is open. Request to {self.api_req.url} blocked."
            )
            raise ApiCircuitOpenError("Circuit breaker is open")

        current_backoff_delay = self.backoff
        last_exception: Optional[Exception] = None

        for attempt in range(self.max_retries + 1):
            try:
                self._logger.debug(
                    f"[API Client] Executing request attempt {attempt + 1}/{self.max_retries + 1} for {self.api_req.url}"
                )
                return await self._perform_single_attempt(request)
            except (ApiTimeoutError, ApiRateLimitError, ApiHttpError) as e:
                self._logger.warning(
                    f"[API Client] Attempt {attempt + 1}/{self.max_retries + 1} for {self.api_req.url} failed with {type(e).__name__}: {e}."
                )
                self.breaker.record_failure()
                self._logger.error(  # type: ignore[call-arg]
                    f"[API Client] Failure recorded for circuit breaker due to error on {self.api_req.url}.",
                    meta={"error": str(e)},
                )
                last_exception = e
                if isinstance(e, ApiHttpError) and e.status_code < 500:
                    self._logger.error(  # type: ignore[call-arg]
                        f"[API Client] Non-retryable HTTP error {e.status_code} for {self.api_req.url}. Not retrying.",
                        meta={"error": str(e)},
                    )
                    raise

                if attempt == self.max_retries:
                    self._logger.error(  # type: ignore[call-arg]
                        f"[API Client] Request to {self.api_req.url} failed after {self.max_retries + 1} attempts. Last error: {type(last_exception).__name__} - {last_exception}",
                        meta={"error": str(last_exception)},
                    )
                    raise

                self._logger.info(
                    f"[API Client] Retrying request to {self.api_req.url} in {current_backoff_delay:.2f} seconds..."
                )
                await asyncio.sleep(current_backoff_delay)
                current_backoff_delay *= 2
            except ApiError as e:
                self._logger.error(  # type: ignore[call-arg]
                    f"[API Client] Unrecoverable API error for {self.api_req.url}: {type(e).__name__} - {e}",
                    meta={"error": str(e)},
                )
                raise e

        if last_exception:
            raise last_exception
        raise ApiError(
            f"[API Client] Max retries ({self.max_retries}) exceeded for {self.api_req.url} without a successful response."
        )
