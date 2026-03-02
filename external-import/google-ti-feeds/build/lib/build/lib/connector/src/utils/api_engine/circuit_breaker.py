"""Simple CircuitBreaker."""

import time

from .interfaces.base_circuit_breaker import BaseCircuitBreaker


class CircuitBreaker(BaseCircuitBreaker):
    """Simple CircuitBreaker."""

    def __init__(self, max_failures: int = 5, cooldown_time: int = 60) -> None:
        """Initialize the CircuitBreaker with max_failures and cooldown_time."""
        self.max_failures = max_failures
        self.cooldown_time = cooldown_time
        self.failure_count = 0
        self.last_failure_time = 0.0

    def is_open(self) -> bool:
        """Check if the CircuitBreaker is open.

        Returns:
            bool: True if the CircuitBreaker is open, False otherwise.

        """
        now = time.time()
        if (
            self.failure_count >= self.max_failures
            and now - self.last_failure_time < self.cooldown_time
        ):
            return True
        if now - self.last_failure_time >= self.cooldown_time:
            self.reset()
        return False

    def record_failure(self) -> None:
        """Record a failure and update the last failure time."""
        self.failure_count += 1
        self.last_failure_time = time.time()

    def reset(self) -> None:
        """Reset the CircuitBreaker."""
        self.failure_count = 0
        self.last_failure_time = 0.0
