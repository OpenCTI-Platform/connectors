"""HTTP client retrying rate-limited, failing and unreachable requests."""

from __future__ import annotations

import random
import time
from collections.abc import Callable
from typing import Any

import requests
from connectors_sdk import (
    ApiClientError,
    ApiRateLimitError,
    BaseClientApi,
    ConnectorLogger,
)

RETRYABLE_STATUS_CODES = frozenset({408, 429, 500, 502, 503, 504})


class RetryingApiClient(BaseClientApi):
    """``BaseClientApi`` with an explicit, logged retry policy.

    A request failing with a status of ``RETRYABLE_STATUS_CODES`` or a
    network error is retried up to ``max_retries`` times, waiting for the
    delay the server asks (``Retry-After``) or an exponential backoff with
    jitter, capped at ``max_backoff`` seconds. Retries are done here rather
    than by urllib3 so they also cover POST requests and are logged.
    """

    def __init__(
        self,
        base_url: str,
        *,
        logger: ConnectorLogger,
        timeout: int = 60,
        ssl_verify: bool = True,
        max_retries: int = 5,
        backoff_factor: float = 1.0,
        max_backoff: float = 60.0,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        super().__init__(
            base_url,
            timeout=timeout,
            ssl_verify=ssl_verify,
            max_retries=0,
            backoff_factor=0,
        )
        self._logger = logger
        self._retries = max_retries
        self._backoff_factor = backoff_factor
        self._max_backoff = max_backoff
        self._sleep = sleep or time.sleep

    def _raw_request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        for attempt in range(self._retries + 1):
            try:
                response = super()._raw_request(method, path, **kwargs)
            except (requests.ConnectionError, requests.Timeout) as err:
                if attempt >= self._retries:
                    raise ApiClientError(
                        f"{method} {path} failed after {attempt + 1} attempt(s): {err}"
                    ) from err
                self._wait(method, path, attempt, None, str(err))
                continue
            if (
                response.status_code in RETRYABLE_STATUS_CODES
                and attempt < self._retries
            ):
                self._wait(
                    method,
                    path,
                    attempt,
                    self.retry_after(response),
                    f"HTTP {response.status_code}",
                )
                continue
            return response
        raise AssertionError("unreachable")  # pragma: no cover

    def retry_after(self, response: requests.Response) -> float | None:
        """Return the delay the server asks before retrying, if any."""
        return ApiRateLimitError.parse_retry_after(response.headers)

    def _wait(
        self,
        method: str,
        path: str,
        attempt: int,
        retry_after: float | None,
        reason: str,
    ) -> None:
        if retry_after is None:
            retry_after = self._backoff_factor * (
                2**attempt
            ) + random.uniform(  # noqa: S311
                0, self._backoff_factor
            )
        delay = max(0.0, min(retry_after, self._max_backoff))
        self._logger.warning(
            "Request failed, retrying",
            {
                "method": method,
                "path": path,
                "reason": reason,
                "attempt": attempt + 1,
                "max_retries": self._retries,
                "delay_seconds": round(delay, 2),
            },
        )
        self._sleep(delay)
