"""BaseRateLimiter Interfaces."""

from abc import ABC, abstractmethod


class BaseRateLimiter(ABC):
    """BaseRateLimiter Interfaces
    This class defines the interface for rate limiters.
    It provides an abstract method for acquiring a token from the rate limiter.
    """

    @abstractmethod
    async def acquire(self) -> None:
        """Acquire a token from the rate limiter.
        This method should be implemented by subclasses to acquire a token from the rate limiter.
        """
        raise NotImplementedError("Subclasses must implement this method")
