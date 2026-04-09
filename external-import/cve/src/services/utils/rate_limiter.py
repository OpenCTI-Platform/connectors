import asyncio
import time
from collections import deque


class AsyncRateLimiter:
    """Sliding-window rate limiter for asyncio.

    Tracks the timestamps of recent requests and ensures no more than
    ``max_per_interval`` requests are made within any ``interval``-second
    window.  Uses ``time.monotonic()`` so the state safely survives across
    multiple ``asyncio.run()`` calls (no event-loop callbacks to leak).

    NVD rate limits:
      - With API key : 50 requests / 30 s
      - Without      :  5 requests / 30 s
    """

    def __init__(self, max_per_interval: int, interval: float) -> None:
        self._max = max_per_interval
        self._interval = interval
        self._timestamps: deque[float] = deque()
        self._lock: asyncio.Lock | None = None

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def acquire(self) -> None:
        """Block until a request slot is available."""
        lock = self._get_lock()
        while True:
            async with lock:
                now = time.monotonic()
                # Purge timestamps outside the sliding window
                while self._timestamps and now - self._timestamps[0] >= self._interval:
                    self._timestamps.popleft()

                if len(self._timestamps) < self._max:
                    self._timestamps.append(now)
                    return

                # Calculate wait until oldest timestamp expires
                wait_time = self._interval - (now - self._timestamps[0]) + 0.05

            await asyncio.sleep(wait_time)

    def reset(self) -> None:
        """Reset the limiter state (e.g. between asyncio.run() calls)."""
        self._timestamps.clear()
        self._lock = None

    @classmethod
    def for_nvd(cls, has_api_key: bool) -> "AsyncRateLimiter":
        """Factory that selects the correct NVD rate limit."""
        if has_api_key:
            return cls(max_per_interval=50, interval=30.0)
        return cls(max_per_interval=5, interval=30.0)
