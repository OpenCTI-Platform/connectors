"""Token bucket rate limiter and registry."""

import asyncio
import logging
import time
from collections import deque
from typing import ClassVar

from .interfaces.base_rate_limiter import BaseRateLimiter

_logger = logging.getLogger(__name__)


class TokenBucketRateLimiter(BaseRateLimiter):
    """Sliding-window rate limiter backed by a timestamp deque."""

    def __init__(self, max_requests: int, period: float) -> None:
        """Initialise with *max_requests* allowed per *period* seconds.

        Args:
            max_requests: Maximum number of requests allowed in the window.
            period: Length of the sliding window in seconds.
        """
        self.max_requests = max_requests
        self.period = period
        self._timestamps: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Block until a request slot is available, then claim it."""
        async with self._lock:
            now = time.monotonic()
            while self._timestamps and self._timestamps[0] + self.period <= now:
                self._timestamps.popleft()

            if len(self._timestamps) >= self.max_requests:
                wait_time = self._timestamps[0] + self.period - now
                _logger.debug(
                    "Rate limit reached (%d/%d), waiting %.3fs",
                    len(self._timestamps),
                    self.max_requests,
                    wait_time,
                )
                await asyncio.sleep(wait_time)
                now = time.monotonic()
                while self._timestamps and self._timestamps[0] + self.period <= now:
                    self._timestamps.popleft()

            self._timestamps.append(time.monotonic())


class RateLimiterRegistry:
    """Singleton-per-key registry of TokenBucketRateLimiter instances."""

    _store: ClassVar[dict[str, TokenBucketRateLimiter]] = {}

    @classmethod
    def get_or_create(
        cls, key: str, max_requests: int, period: float
    ) -> TokenBucketRateLimiter:
        """Return existing limiter for *key* or create a new one.

        Args:
            key: Unique registry key for this limiter.
            max_requests: Maximum requests per window for a new limiter.
            period: Window duration in seconds for a new limiter.

        Returns:
            Existing or newly created TokenBucketRateLimiter.
        """
        if key not in cls._store:
            cls._store[key] = TokenBucketRateLimiter(
                max_requests=max_requests, period=period
            )
        return cls._store[key]

    @classmethod
    def clear(cls) -> None:
        """Remove all registered limiters (for test isolation)."""
        cls._store.clear()
