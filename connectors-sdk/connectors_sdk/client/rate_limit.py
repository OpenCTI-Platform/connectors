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
        raise_on_limit_exceeded: If True (default), raise ``ApiRateLimitError``
            when the limit is exceeded. If False, sleep until the window resets.
        **kwargs: Passed to ``HTTPAdapter``.
    """

    def __init__(
        self,
        rate_limit: RateLimit | str | None = None,
        rate_limit_key: str = "default",
        raise_on_limit_exceeded: bool = True,
        **kwargs: Any,
    ) -> None:
        self._limiter: strategies.FixedWindowRateLimiter | None = None
        self._rate_limit_item = None
        if rate_limit:
            self._rate_limit_item = parse(str(rate_limit))
            self._limiter = strategies.FixedWindowRateLimiter(storage.MemoryStorage())
        self._rate_limit_key = rate_limit_key
        self._raise_on_limit_exceeded = raise_on_limit_exceeded
        super().__init__(**kwargs)

    def send(
        self, request: requests.PreparedRequest, **kwargs: Any
    ) -> requests.Response:
        """Check rate limit before sending the request."""
        if self._limiter and self._rate_limit_item:
            if not self._limiter.hit(self._rate_limit_item, self._rate_limit_key):
                self._wait_or_raise()
        return super().send(request, **kwargs)

    def _wait_or_raise(self) -> None:
        """Either raise ApiRateLimitError or sleep until a token is available."""
        assert self._limiter is not None  # noqa: S101 (guarded by caller)
        assert self._rate_limit_item is not None  # noqa: S101

        window_stats = self._limiter.get_window_stats(
            self._rate_limit_item, self._rate_limit_key
        )
        wait_time = float(max(window_stats.reset_time - time.time(), 0))

        if self._raise_on_limit_exceeded:
            raise ApiRateLimitError(
                f"Rate limit exceeded ({self._rate_limit_item})",
                retry_after=wait_time,
            )

        # Block mode: sleep until the window resets
        while True:
            sleep_for = max(wait_time, 0.01)
            logger.debug("Rate limit reached, sleeping %.2f seconds", sleep_for)
            time.sleep(sleep_for)
            if self._limiter.hit(self._rate_limit_item, self._rate_limit_key):
                break
            window_stats = self._limiter.get_window_stats(
                self._rate_limit_item, self._rate_limit_key
            )
            wait_time = float(max(window_stats.reset_time - time.time(), 0))
