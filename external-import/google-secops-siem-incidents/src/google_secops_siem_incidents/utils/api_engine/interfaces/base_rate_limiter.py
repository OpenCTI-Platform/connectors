"""Base rate limiter interface."""

from abc import ABC, abstractmethod


class BaseRateLimiter(ABC):
    """Abstract async rate limiter."""

    @abstractmethod
    async def acquire(self) -> None:
        """Acquire a rate-limit slot, blocking if necessary."""
        ...
