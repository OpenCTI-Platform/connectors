"""Time helpers of the hunt connectors: run deadline and event timestamps."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from connectors_sdk.connectors.internal_hunt.errors import HuntTimeoutError


class RunDeadline:
    """Deadline of a hunt run, used to bound the platform API calls and job polling.

    Examples:
        >>> deadline = RunDeadline(limits.timeout_seconds)
        >>> while not job_is_done():
        ...     deadline.check("Splunk search job")
        ...     deadline.sleep(2)
    """

    def __init__(
        self,
        timeout_seconds: float,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        """Start the deadline.

        Args:
            timeout_seconds: Time budget of the run.
            clock: Monotonic clock (injectable for tests).
            sleeper: Sleep function (injectable for tests).
        """
        self._clock = clock
        self._sleeper = sleeper
        self._expires_at = clock() + timeout_seconds

    def remaining(self) -> float:
        """Return the seconds left before the deadline (never negative)."""
        return max(0.0, self._expires_at - self._clock())

    def expired(self) -> bool:
        """Return whether the deadline is reached."""
        return self.remaining() <= 0

    def request_timeout(self, maximum: float = 60.0, minimum: float = 1.0) -> float:
        """Return the timeout of the next HTTP request.

        Args:
            maximum: Upper bound of a single request.
            minimum: Lower bound, so that a request is never sent without timeout.

        Returns:
            The remaining time, bounded by ``minimum`` and ``maximum``.
        """
        return max(minimum, min(maximum, self.remaining()))

    def check(self, operation: str) -> None:
        """Raise when the deadline is reached.

        Args:
            operation: Description of the running operation, for the error message.

        Raises:
            HuntTimeoutError: If the deadline is reached.
        """
        if self.expired():
            raise HuntTimeoutError(f"{operation} did not complete within the run timeout.")

    def sleep(self, seconds: float) -> None:
        """Sleep without going past the deadline.

        Args:
            seconds: Requested sleep duration.
        """
        self._sleeper(max(0.0, min(seconds, self.remaining())))


def parse_timestamp(value: Any) -> datetime | None:
    """Parse an event time sent by a platform.

    Accepts ISO 8601 strings (``Z`` or offset suffix; naive values are read as
    UTC), epoch seconds and epoch milliseconds (numbers or digit strings).

    Args:
        value: Raw event time.

    Returns:
        A timezone-aware datetime, or ``None`` when the value is not a time.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        value = int(value.strip())
    if isinstance(value, (int, float)):
        seconds = value / 1000 if abs(value) >= 1e11 else value
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
