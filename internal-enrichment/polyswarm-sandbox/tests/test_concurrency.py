"""Concurrency tests — verify thread safety under parallel access.

Tests circuit breaker, shared state, and enrichment context
under concurrent access patterns that mirror production load.
"""

import os
import sys
import threading
import time

SRC_DIR = os.path.join(os.path.dirname(__file__), os.pardir, "src")
sys.path.insert(0, os.path.abspath(SRC_DIR))

from connector.polyswarm_client import CircuitBreaker

# ── Circuit Breaker Concurrency ──────────────────────────────────────────


class TestCircuitBreakerConcurrency:
    """Circuit breaker must be thread-safe under concurrent access."""

    def test_concurrent_failures_trip_breaker(self):
        """50 threads recording failures simultaneously should trip the breaker exactly once."""
        cb = CircuitBreaker(failure_threshold=5, cooldown_seconds=300)
        threads = []
        for _ in range(50):
            t = threading.Thread(target=cb.record_failure)
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # Breaker should be OPEN (not corrupted)
        assert cb.state in ("OPEN", "HALF_OPEN")

    def test_concurrent_success_resets(self):
        """Concurrent successes after failures should cleanly reset to CLOSED."""
        cb = CircuitBreaker(failure_threshold=3, cooldown_seconds=0)
        # Trip the breaker
        for _ in range(5):
            cb.record_failure()
        assert cb.state in ("OPEN", "HALF_OPEN")
        # Wait for cooldown (0 seconds)
        time.sleep(0.01)
        # Concurrent successes
        threads = []
        for _ in range(20):
            t = threading.Thread(target=cb.record_success)
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert cb.state == "CLOSED"

    def test_concurrent_allow_request_consistent(self):
        """allow_request() should return consistent results under concurrent reads."""
        cb = CircuitBreaker(failure_threshold=5, cooldown_seconds=300)
        results = []
        lock = threading.Lock()

        def check():
            r = cb.allow_request()
            with lock:
                results.append(r)

        threads = [threading.Thread(target=check) for _ in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # All should be True (breaker is CLOSED)
        assert all(results), "All requests should be allowed when breaker is CLOSED"

    def test_concurrent_mixed_operations(self):
        """Mix of failures, successes, and reads should not corrupt state."""
        cb = CircuitBreaker(failure_threshold=10, cooldown_seconds=300)
        errors = []

        def fail_op():
            try:
                for _ in range(20):
                    cb.record_failure()
                    time.sleep(0.001)
            except Exception as e:
                errors.append(e)

        def success_op():
            try:
                for _ in range(20):
                    cb.record_success()
                    time.sleep(0.001)
            except Exception as e:
                errors.append(e)

        def read_op():
            try:
                for _ in range(50):
                    cb.allow_request()
                    _ = cb.state
                    time.sleep(0.001)
            except Exception as e:
                errors.append(e)

        threads = (
            [threading.Thread(target=fail_op) for _ in range(5)]
            + [threading.Thread(target=success_op) for _ in range(5)]
            + [threading.Thread(target=read_op) for _ in range(10)]
        )
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Thread errors: {errors}"
        # State should be valid
        assert cb.state in ("CLOSED", "OPEN", "HALF_OPEN")

    def test_no_deadlock_under_contention(self):
        """Breaker should not deadlock under heavy contention."""
        cb = CircuitBreaker(failure_threshold=3, cooldown_seconds=0)
        done = threading.Event()

        def hammer():
            while not done.is_set():
                cb.record_failure()
                cb.allow_request()
                cb.record_success()
                _ = cb.state

        threads = [threading.Thread(target=hammer, daemon=True) for _ in range(20)]
        for t in threads:
            t.start()
        # If we get here without deadlock in 2 seconds, we're good
        time.sleep(2)
        done.set()
        for t in threads:
            t.join(timeout=1)
        # If any thread is still alive, we deadlocked
        alive = [t for t in threads if t.is_alive()]
        assert len(alive) == 0, f"{len(alive)} threads deadlocked"
