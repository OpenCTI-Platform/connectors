"""Rate-limiting HTTP adapter for OpenCTI connectors."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Literal

import requests
from connectors_sdk.client.exceptions import ApiRateLimitError
from limits import parse, storage, strategies
from requests.adapters import HTTPAdapter


@dataclass(frozen=True)
class RateLimit:
    """Type-safe rate limit specification with IDE completion support.

    Args:
        limit: Number of requests allowed within the time window.
        period: Time window granularity.

    Example::

        RateLimit(100, "minute")   # 100 requests per minute
        RateLimit(5000, "hour")    # 5 000 requests per hour
        RateLimit(10, "second")    # 10 requests per second
    """

    limit: int
    period: Literal["second", "minute", "hour", "day"]

    def __str__(self) -> str:
        """Return the ``limits``-library string representation."""
        return f"{self.limit}/{self.period}"


logger = logging.getLogger(__name__)


class _RateLimitAdapter(HTTPAdapter):  # type: ignore[misc]
    """HTTPAdapter that enforces a proactive rate limit before every send.

    This applies to each attempt including urllib3 retries, ensuring we never
    exceed the configured rate even during transient-error retry loops.

    Args:
        rate_limit: Rate limit string in ``limits`` notation.
        rate_limit_key: Key to scope the rate limit (usually the base URL).
        rate_limit_block: If True, sleep until the window resets instead of
            raising ``ApiRateLimitError``.
        **kwargs: Passed to ``HTTPAdapter``.
    """

    def __init__(
        self,
        rate_limit: RateLimit | str | None = None,
        rate_limit_key: str = "default",
        rate_limit_block: bool = False,
        **kwargs: Any,
    ) -> None:
        self._limiter: strategies.FixedWindowRateLimiter | None = None
        self._rate_limit_item = None
        if rate_limit:
            self._rate_limit_item = parse(str(rate_limit))
            self._limiter = strategies.FixedWindowRateLimiter(storage.MemoryStorage())
        self._rate_limit_key = rate_limit_key
        self._rate_limit_block = rate_limit_block
        super().__init__(**kwargs)

    def send(
        self, request: requests.PreparedRequest, **kwargs: Any
    ) -> requests.Response:
        """Check rate limit before sending the request."""
        if self._limiter and self._rate_limit_item:
            if not self._limiter.hit(self._rate_limit_item, self._rate_limit_key):
                if self._rate_limit_block:
                    self._wait_for_token()
                else:
                    window_stats = self._limiter.get_window_stats(
                        self._rate_limit_item, self._rate_limit_key
                    )
                    wait_time = float(max(window_stats.reset_time - time.time(), 0))
                    raise ApiRateLimitError(
                        f"Rate limit exceeded ({self._rate_limit_item})",
                        retry_after=wait_time,
                    )
        return super().send(request, **kwargs)

    def _wait_for_token(self) -> None:
        """Sleep until a rate-limit token becomes available, then consume it."""
        assert self._limiter is not None  # noqa: S101 (guarded by caller)
        assert self._rate_limit_item is not None  # noqa: S101
        while True:
            window_stats = self._limiter.get_window_stats(
                self._rate_limit_item, self._rate_limit_key
            )
            wait_time = float(max(window_stats.reset_time - time.time(), 0))
            logger.debug("Rate limit reached, sleeping %.2f seconds", wait_time)
            time.sleep(wait_time)
            if self._limiter.hit(self._rate_limit_item, self._rate_limit_key):
                break
