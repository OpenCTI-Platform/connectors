"""Base circuit breaker interface."""

from abc import ABC, abstractmethod


class BaseCircuitBreaker(ABC):
    """Abstract circuit breaker."""

    @abstractmethod
    def is_open(self) -> bool:
        """Return True if the circuit is currently open."""
        ...

    @abstractmethod
    def record_failure(self) -> None:
        """Record a single failure event."""
        ...

    @abstractmethod
    def reset(self) -> None:
        """Reset the circuit to closed state."""
        ...
