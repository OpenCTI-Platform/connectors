"""Circuit breaker implementation."""

import logging
import time

from .interfaces.base_circuit_breaker import BaseCircuitBreaker


class CircuitBreaker(BaseCircuitBreaker):
    """Tracks consecutive failures and opens the circuit once a threshold is reached."""

    def __init__(
        self,
        max_failures: int = 5,
        cooldown_time: float = 60.0,
        logger: logging.Logger | None = None,
    ) -> None:
        """Initialise with failure threshold and cooldown period.

        Args:
            max_failures: Number of failures before the circuit opens.
            cooldown_time: Seconds to wait before resetting after opening.
            logger: Optional logger; defaults to module logger.
        """
        self.max_failures = max_failures
        self.cooldown_time = cooldown_time
        self.failure_count: int = 0
        self.last_failure_time: float = 0.0
        self._logger = logger or logging.getLogger(__name__)

    def _maybe_reset(self) -> None:
        """Reset failure count if the cooldown window has passed."""
        if (
            self.failure_count >= self.max_failures
            and time.time() - self.last_failure_time >= self.cooldown_time
        ):
            self.failure_count = 0
            self.last_failure_time = 0.0

    def is_open(self) -> bool:
        """Return True if the circuit is open (too many failures within cooldown).

        Returns:
            True if requests should be blocked.
        """
        self._maybe_reset()
        return self.failure_count >= self.max_failures

    def record_failure(self) -> None:
        """Record a single failure and update the failure timestamp."""
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.max_failures:
            self._logger.warning("Circuit opened after %d failures", self.failure_count)

    def reset(self) -> None:
        """Explicitly reset the circuit to closed state."""
        self.failure_count = 0
        self.last_failure_time = 0.0
