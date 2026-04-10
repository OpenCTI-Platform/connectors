import asyncio
import time
from collections import deque

# NVD rate limit with API key: 50 requests per rolling 30-second window.
# See https://nvd.nist.gov/developers/start-here#rate-limits
NVD_MAX_REQUESTS = 50
NVD_INTERVAL_SECONDS = 30.0


class AsyncRateLimiter:
    """Sliding-window rate limiter for asyncio.

    Tracks the timestamps of recent requests and ensures no more than
    ``NVD_MAX_REQUESTS`` requests are made within any rolling
    ``NVD_INTERVAL_SECONDS`` window.  Uses ``time.monotonic()`` so the
    state safely survives across multiple ``asyncio.run()`` calls.
    """

    def __init__(self) -> None:
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
                while (
                    self._timestamps
                    and now - self._timestamps[0] >= NVD_INTERVAL_SECONDS
                ):
                    self._timestamps.popleft()

                if len(self._timestamps) < NVD_MAX_REQUESTS:
                    self._timestamps.append(now)
                    return

                # Calculate wait until oldest timestamp expires
                wait_time = NVD_INTERVAL_SECONDS - (now - self._timestamps[0]) + 0.05

            await asyncio.sleep(wait_time)

    def reset(self) -> None:
        """Reset the limiter state (e.g. between asyncio.run() calls)."""
        self._timestamps.clear()
        self._lock = None
