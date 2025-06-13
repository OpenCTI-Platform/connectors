"""Rate limiter module."""

import asyncio
import time
from collections import deque
from typing import Dict

from .interfaces.base_rate_limiter import BaseRateLimiter


class TokenBucketRateLimiter(BaseRateLimiter):
    """Token bucket rate limiter implementation."""

    def __init__(self, max_requests: int, period: int) -> None:
        """Initialize the token bucket rate limiter."""
        self.max_requests = max_requests
        self.period = period
        self.timestamps: deque[float] = deque()
        self.lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire a token from the rate limiter."""
        async with self.lock:
            now = time.time()
            while self.timestamps and now - self.timestamps[0] > self.period:
                self.timestamps.popleft()

            if len(self.timestamps) >= self.max_requests:
                sleep = self.period - (now - self.timestamps[0])
                await asyncio.sleep(sleep)

            self.timestamps.append(time.time())


class RateLimiterRegistry:
    """Rate limiter registry implementation."""

    _store: Dict[str, BaseRateLimiter] = {}
    _lock = asyncio.Lock()

    @classmethod
    async def get(cls, key: str, max_requests: int, period: int) -> BaseRateLimiter:
        """Get a rate limiter from the registry.

        Args:
            key: The key to use for the rate limiter.
            max_requests: The maximum number of requests allowed.
            period: The period in seconds for the rate limiter.

        Returns:
            The rate limiter instance.

        """
        async with cls._lock:
            if key not in cls._store:
                cls._store[key] = TokenBucketRateLimiter(max_requests, period)
            return cls._store[key]
