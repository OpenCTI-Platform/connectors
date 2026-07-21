"""RED tests for Feature: Circuit Breaker Protection.

Tests that CircuitBreaker tracks failures and transitions between
closed / open states based on a configurable threshold.

All tests MUST fail with ImportError until the implementation exists.
"""

from google_secops_siem_incidents.utils.api_engine.circuit_breaker import CircuitBreaker


# ---------------------------------------------------------------------------
# Scenario: Circuit starts in closed state
# ---------------------------------------------------------------------------
def test_circuit_starts_in_closed_state():
    """A freshly created circuit breaker is closed."""

    def _given_circuit_breaker():
        return CircuitBreaker(max_failures=3, cooldown_time=60)

    def _then_circuit_is_closed(cb):
        assert cb.is_open() is False

    cb = _given_circuit_breaker()
    _then_circuit_is_closed(cb)


# ---------------------------------------------------------------------------
# Scenario: Single failure below threshold does not open the circuit
# ---------------------------------------------------------------------------
def test_single_failure_below_threshold_does_not_open_circuit():
    """One failure keeps the circuit closed."""

    def _given_circuit_breaker():
        return CircuitBreaker(max_failures=3, cooldown_time=60)

    def _when_a_failure_is_recorded(cb):
        cb.record_failure()
        return cb

    def _then_circuit_remains_closed(cb):
        assert cb.is_open() is False

    cb = _given_circuit_breaker()
    cb = _when_a_failure_is_recorded(cb)
    _then_circuit_remains_closed(cb)


# ---------------------------------------------------------------------------
# Scenario: Reaching the failure threshold opens the circuit
# ---------------------------------------------------------------------------
def test_reaching_failure_threshold_opens_circuit():
    """Recording max_failures failures opens the circuit."""

    def _given_circuit_breaker():
        return CircuitBreaker(max_failures=3, cooldown_time=60)

    def _when_failure_recorded_n_times(cb, n):
        for _ in range(n):
            cb.record_failure()
        return cb

    def _then_circuit_is_open(cb):
        assert cb.is_open() is True

    cb = _given_circuit_breaker()
    cb = _when_failure_recorded_n_times(cb, 3)
    _then_circuit_is_open(cb)


# ---------------------------------------------------------------------------
# Scenario: Open circuit rejects subsequent checks
# ---------------------------------------------------------------------------
def test_open_circuit_rejects_subsequent_checks():
    """Once open, is_open() continues to return True within cooldown."""

    def _given_circuit_at_threshold():
        cb = CircuitBreaker(max_failures=3, cooldown_time=60)
        for _ in range(3):
            cb.record_failure()
        return cb

    def _when_circuit_is_checked(cb):
        return cb.is_open()

    def _then_circuit_is_open(result):
        assert result is True

    cb = _given_circuit_at_threshold()
    result = _when_circuit_is_checked(cb)
    _then_circuit_is_open(result)


# ---------------------------------------------------------------------------
# Scenario: Circuit is reset to closed state explicitly
# ---------------------------------------------------------------------------
def test_circuit_reset_to_closed_state():
    """Calling reset() after threshold closes the circuit."""

    def _given_circuit_at_threshold():
        cb = CircuitBreaker(max_failures=3, cooldown_time=60)
        for _ in range(3):
            cb.record_failure()
        return cb

    def _when_circuit_is_reset(cb):
        cb.reset()
        return cb

    def _then_circuit_is_closed(cb):
        assert cb.is_open() is False

    cb = _given_circuit_at_threshold()
    cb = _when_circuit_is_reset(cb)
    _then_circuit_is_closed(cb)


# ---------------------------------------------------------------------------
# Design constraint: instance-level state (not class attrs)
# ---------------------------------------------------------------------------
def test_circuit_breaker_uses_instance_level_state():
    """Two CircuitBreaker instances MUST NOT share failure state."""

    def _given_two_independent_circuit_breakers():
        cb_a = CircuitBreaker(max_failures=3, cooldown_time=60)
        cb_b = CircuitBreaker(max_failures=3, cooldown_time=60)
        return cb_a, cb_b

    def _when_first_breaker_reaches_threshold(cb_a):
        for _ in range(3):
            cb_a.record_failure()
        return cb_a

    def _then_second_breaker_is_unaffected(cb_b):
        assert cb_b.is_open() is False

    cb_a, cb_b = _given_two_independent_circuit_breakers()
    _when_first_breaker_reaches_threshold(cb_a)
    _then_second_breaker_is_unaffected(cb_b)
