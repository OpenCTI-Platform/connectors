"""RED tests for Feature: Circuit Failure Accumulation.

Tests that failures accumulate over multiple interactions and that
the circuit auto-recovers after the recovery window expires.

All tests MUST fail with ImportError until the implementation exists.
"""

import time

from google_secops_siem_incidents.utils.api_engine.circuit_breaker import CircuitBreaker


# ---------------------------------------------------------------------------
# Scenario: Failures below the threshold leave the circuit closed
# ---------------------------------------------------------------------------
def test_failures_below_threshold_leave_circuit_closed():
    """2 failures with threshold=3 keeps the circuit closed."""

    def _given_circuit_breaker():
        return CircuitBreaker(max_failures=3, cooldown_time=1)

    def _when_failure_recorded_across_separate_calls(cb, n):
        for _ in range(n):
            cb.record_failure()
        return cb

    def _then_circuit_remains_closed(cb):
        assert cb.is_open() is False

    cb = _given_circuit_breaker()
    cb = _when_failure_recorded_across_separate_calls(cb, 2)
    _then_circuit_remains_closed(cb)


# ---------------------------------------------------------------------------
# Scenario: Accumulated failures reaching the threshold open the circuit
# ---------------------------------------------------------------------------
def test_accumulated_failures_reaching_threshold_open_circuit():
    """3 failures with threshold=3 opens the circuit."""

    def _given_circuit_breaker():
        return CircuitBreaker(max_failures=3, cooldown_time=1)

    def _when_failure_recorded_across_separate_calls(cb, n):
        for _ in range(n):
            cb.record_failure()
        return cb

    def _then_circuit_is_open(cb):
        assert cb.is_open() is True

    cb = _given_circuit_breaker()
    cb = _when_failure_recorded_across_separate_calls(cb, 3)
    _then_circuit_is_open(cb)


# ---------------------------------------------------------------------------
# Scenario: Circuit auto-recovers after the recovery window expires
# ---------------------------------------------------------------------------
def test_circuit_auto_recovers_after_recovery_window_expires():
    """After cooldown_time elapses, is_open() returns False."""

    def _given_circuit_opened_by_3_failures():
        cb = CircuitBreaker(max_failures=3, cooldown_time=0.1)
        for _ in range(3):
            cb.record_failure()
        return cb

    def _when_recovery_window_elapses(cb):
        time.sleep(0.15)
        return cb

    def _then_circuit_is_closed_again(cb):
        assert cb.is_open() is False

    cb = _given_circuit_opened_by_3_failures()
    cb = _when_recovery_window_elapses(cb)
    _then_circuit_is_closed_again(cb)
