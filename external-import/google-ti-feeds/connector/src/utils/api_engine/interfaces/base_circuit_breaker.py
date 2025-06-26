"""Base circuit breaker interface."""

from abc import ABC, abstractmethod


class BaseCircuitBreaker(ABC):
    """Base circuit breaker interface.

    This interface defines the basic methods for a circuit breaker.
    """

    max_failures = 5
    cooldown_time = 60
    failure_count = 0
    last_failure_time = 0.0

    @abstractmethod
    def is_open(self) -> bool:
        """Check if the circuit breaker is open."""
        raise NotImplementedError("Subclass must implement this method.")

    @abstractmethod
    def record_failure(self) -> None:
        """Record a failure attempt."""
        raise NotImplementedError("Subclass must implement this method.")

    @abstractmethod
    def reset(self) -> None:
        """Reset the circuit breaker."""
        raise NotImplementedError("Subclass must implement this method.")
