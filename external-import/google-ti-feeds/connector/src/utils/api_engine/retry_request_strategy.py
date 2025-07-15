"""Base retry request strategy with hooks handling."""

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Any, Dict, Optional, Union

from .api_request_model import ApiRequestModel
from .exceptions.api_circuit_open_error import ApiCircuitOpenError
from .exceptions.api_error import ApiError
from .exceptions.api_http_error import ApiHttpError
from .exceptions.api_network_error import ApiNetworkError
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

LOG_PREFIX = "[API Retry Strategy]"


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
                ValueError: If max_retries is less than 0.
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
                    f"{LOG_PREFIX} Missing required keys in limiter config: {missing_keys}"
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
                f"{LOG_PREFIX} Rate limiter initialized with key {self._limiter_config['key']}",
                f"max_requests={self._limiter_config['max_requests']}, period={self._limiter_config['period']}",
            )

        self._initialized = True

    async def _perform_single_attempt(self) -> Any:
        """Perform a single request attempt and process response."""
        try:
            await self._initialize()

            if self.limiter:
                await self.limiter.acquire()
                self._logger.debug(
                    f"{LOG_PREFIX} Rate limiter token acquired for {self.api_req.url}"
                )

            for hook in self.hooks:
                await hook.before(self.api_req)

            self._logger.debug(
                f"{LOG_PREFIX} Attempting {self.api_req.method} to {self.api_req.url} (Headers: {self.api_req.headers is not None}, "
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
            self._logger.debug(
                f"{LOG_PREFIX} Raw response received from {self.api_req.url}"
            )

            for hook in self.hooks:
                await hook.after(self.api_req, raw)

            data = (
                raw.get(self.api_req.response_key) if self.api_req.response_key else raw
            )

            if self.api_req.model:
                try:
                    return self.api_req.model.model_validate(data)
                except Exception as validation_err:
                    self._logger.error(
                        f"{LOG_PREFIX} Response validation failed: {validation_err}",
                    )
                    raise ApiValidationError(
                        f"Response validation failed: {str(validation_err)}"
                    ) from validation_err
            self._logger.debug(
                f"{LOG_PREFIX} Successfully processed request to {self.api_req.url}"
            )
            return data
        except (
            ApiTimeoutError,
            ApiRateLimitError,
            ApiHttpError,
            ApiValidationError,
            ApiCircuitOpenError,
        ) as known_api_err:
            self._logger.warning(
                f"{LOG_PREFIX} Known API error during attempt for {self.api_req.url}: {type(known_api_err).__name__} - {known_api_err}"
            )
            raise known_api_err
        except ApiError as other_api_err:
            self._logger.warning(
                f"{LOG_PREFIX} API error during attempt for {self.api_req.url}: {other_api_err}"
            )
            raise other_api_err
        except Exception as generic_err:
            self._logger.error(
                f"{LOG_PREFIX} Unexpected error during single attempt for {self.api_req.url}",
            )
            raise ApiError(
                f"{LOG_PREFIX} Unexpected error occurred during request processing: {str(generic_err)}"
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
            ApiNetworkError: If there's a persistent network connectivity issue.
            ApiError: If the request fails.

        """
        await self._validate_request(request)

        current_backoff_delay = self.backoff
        last_exception: Optional[Exception] = None
        network_error_count = 0
        max_network_errors = min(self.max_retries, 3)

        for attempt in range(self.max_retries + 1):
            try:
                self._logger.debug(
                    f"{LOG_PREFIX} Executing request attempt {attempt + 1}/{self.max_retries + 1} for {self.api_req.url}"
                )
                return await self._perform_single_attempt()
            except ApiNetworkError as e:
                last_exception = e
                network_error_count += 1
                current_backoff_delay = await self._handle_network_error(
                    e,
                    attempt,
                    network_error_count,
                    max_network_errors,
                    current_backoff_delay,
                )
            except (ApiTimeoutError, ApiRateLimitError, ApiHttpError) as e:
                last_exception = e
                network_error_count = 0
                await self._handle_api_error(e, attempt, current_backoff_delay)
                current_backoff_delay *= 2
            except ApiCircuitOpenError:
                self._logger.info(
                    f"{LOG_PREFIX} Circuit breaker open, waiting before retry..."
                )
                await self._wait_for_circuit_to_close()
                attempt -= 1
            except ApiError as e:
                await self._handle_unrecoverable_error(e)
                raise e

        return await self._handle_max_retries_exceeded(last_exception)

    async def _validate_request(self, request: BaseRequestModel) -> None:
        """Validate the request and check circuit breaker status.

        Args:
            request: The request to validate.

        Raises:
            TypeError: If the request is not an ApiRequestModel.
            ApiCircuitOpenError: If the circuit breaker is open.

        """
        if not isinstance(request, ApiRequestModel):
            self._logger.error(
                f"{LOG_PREFIX} RetryRequestStrategy only supports ApiRequestModel",
            )
            raise TypeError("RetryRequestStrategy only supports ApiRequestModel")

        self.api_req: ApiRequestModel = request

        if self.breaker.is_open():
            self._logger.warning(
                f"{LOG_PREFIX} Circuit breaker is open. Request to {self.api_req.url} blocked."
            )
            await self._wait_for_circuit_to_close()

    async def _handle_network_error(
        self,
        error: ApiNetworkError,
        attempt: int,
        network_error_count: int,
        max_network_errors: int,
        current_backoff_delay: int,
    ) -> int:
        """Handle network errors with appropriate backoff and retries.

        Args:
            error: The network error that occurred.
            attempt: The current attempt number.
            network_error_count: The count of consecutive network errors.
            max_network_errors: The maximum allowed consecutive network errors.
            current_backoff_delay: The current backoff delay.

        Returns:
            The updated backoff delay.

        Raises:
            ApiNetworkError: If max network errors are exceeded.

        """
        self._logger.warning(
            f"{LOG_PREFIX} Network connectivity issue on attempt {attempt + 1}/{self.max_retries + 1} for {self.api_req.url}: {error}"
        )
        self.breaker.record_failure()

        if network_error_count >= max_network_errors:
            self._logger.error(
                f"{LOG_PREFIX} Persistent network connectivity issues detected after {network_error_count} consecutive failures for {self.api_req.url}.",
            )
            raise ApiNetworkError(
                f"Persistent network connectivity issues: {error}"
            ) from error

        if attempt < self.max_retries:
            backoff_time = current_backoff_delay * (1.5 ** (network_error_count - 1))
            self._logger.info(
                f"{LOG_PREFIX} Network error detected. Backing off for {backoff_time:.2f} seconds before retry..."
            )
            await asyncio.sleep(backoff_time)
            return int(backoff_time)

        return current_backoff_delay

    async def _handle_api_error(
        self,
        error: Union[ApiTimeoutError, ApiRateLimitError, ApiHttpError],
        attempt: int,
        current_backoff_delay: int,
    ) -> None:
        """Handle API errors with appropriate logging and retries.

        Args:
            error: The API error that occurred.
            attempt: The current attempt number.
            current_backoff_delay: The current backoff delay.

        Raises:
            ApiHttpError: If the error is a non-retryable HTTP error.
            ApiError: If the maximum number of retries is reached.

        """
        self._logger.warning(
            f"{LOG_PREFIX} Attempt {attempt + 1}/{self.max_retries + 1} for {self.api_req.url} failed with {type(error).__name__}: {error}."
        )
        if not (isinstance(error, ApiHttpError) and error.status_code == 404):
            self.breaker.record_failure()

            self._logger.error(
                f"{LOG_PREFIX} Failure recorded for circuit breaker due to error on {self.api_req.url}.",
            )
        else:
            self._logger.info(
                f"{LOG_PREFIX} 404 error detected for {self.api_req.url} - Not counting toward circuit breaker failures."
            )

        if isinstance(error, ApiHttpError) and error.status_code < 500:
            self._logger.error(
                f"{LOG_PREFIX} Non-retryable HTTP error {error.status_code} for {self.api_req.url}. Not retrying.",
            )
            raise

        self._logger.info(
            f"{LOG_PREFIX} Retrying request to {self.api_req.url} in {current_backoff_delay:.2f} seconds..."
        )
        await asyncio.sleep(current_backoff_delay)

    async def _wait_for_circuit_to_close(self) -> None:
        """Wait until the circuit breaker is closed.

        This method waits for the cooldown period and then resets the circuit breaker.
        """
        if not self.breaker.is_open():
            return

        cooldown_time = self.breaker.cooldown_time
        self._logger.info(
            f"{LOG_PREFIX} Circuit breaker is open. Waiting {cooldown_time} seconds before retry..."
        )
        await asyncio.sleep(cooldown_time)

        if hasattr(self.breaker, "last_failure_time"):
            now = time.time()
            if now - self.breaker.last_failure_time >= cooldown_time:
                self._logger.info(
                    f"{LOG_PREFIX} Cooldown period completed, resetting circuit breaker."
                )
                self.breaker.reset()

    async def _handle_unrecoverable_error(self, error: ApiError) -> None:
        """Handle unrecoverable API errors.

        Args:
            error: The unrecoverable API error.

        """
        self._logger.error(
            f"{LOG_PREFIX} Unrecoverable API error for {self.api_req.url}: {type(error).__name__} - {error}",
        )

    async def _handle_max_retries_exceeded(
        self, last_exception: Optional[Exception]
    ) -> None:
        """Handle the case when maximum retries are exceeded.

        Args:
            last_exception: The last exception that occurred.

        Raises:
            Exception: Re-raises the last exception if there was one.
            ApiError: If max retries are exceeded without a specific exception.

        """
        if last_exception:
            raise last_exception
        raise ApiError(
            f"{LOG_PREFIX} Max retries ({self.max_retries}) exceeded for {self.api_req.url} without a successful response."
        )
