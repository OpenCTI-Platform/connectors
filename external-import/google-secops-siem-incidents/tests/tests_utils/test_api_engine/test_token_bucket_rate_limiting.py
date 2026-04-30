"""RED tests for Feature: Token Bucket Rate Limiting.

Tests that TokenBucketRateLimiter controls request rates and that
RateLimiterRegistry manages named limiter instances.


All tests MUST fail with ImportError until the implementation exists.
"""

import time

import pytest
from google_secops_siem_incidents.utils.api_engine.rate_limiter import (
    RateLimiterRegistry,
    TokenBucketRateLimiter,
)


# ---------------------------------------------------------------------------
# Fixture: isolate registry between tests
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def clear_registry():
    """RateLimiterRegistry.clear() MUST exist for test isolation."""
    RateLimiterRegistry.clear()
    yield
    RateLimiterRegistry.clear()


# ---------------------------------------------------------------------------
# Scenario: Request slot is granted immediately when quota is available
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_request_slot_granted_immediately_when_quota_available():
    """First request within quota completes without delay."""

    async def _given_rate_limiter():
        return TokenBucketRateLimiter(max_requests=10, period=60)

    async def _when_slot_is_acquired(limiter):
        start = time.monotonic()
        await limiter.acquire()
        elapsed = time.monotonic() - start
        return elapsed

    def _then_slot_granted_without_waiting(elapsed):
        assert elapsed < 1.0, "Slot should be granted instantly"

    limiter = await _given_rate_limiter()
    elapsed = await _when_slot_is_acquired(limiter)
    _then_slot_granted_without_waiting(elapsed)


# ---------------------------------------------------------------------------
# Scenario: Request slot is delayed when the quota window is full
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_request_slot_delayed_when_quota_window_full():
    """Third request with max_requests=2 blocks until the window slides."""

    async def _given_rate_limiter_with_2_slots_consumed():
        limiter = TokenBucketRateLimiter(max_requests=2, period=0.5)
        await limiter.acquire()
        await limiter.acquire()
        return limiter

    async def _when_third_slot_acquired(limiter):
        start = time.monotonic()
        await limiter.acquire()
        elapsed = time.monotonic() - start
        return elapsed

    def _then_slot_granted_after_window_slides(elapsed):
        assert elapsed >= 0.3, "Should wait for the oldest request to age out"

    limiter = await _given_rate_limiter_with_2_slots_consumed()
    elapsed = await _when_third_slot_acquired(limiter)
    _then_slot_granted_after_window_slides(elapsed)


# ---------------------------------------------------------------------------
# Scenario: Registry returns the same rate limiter for the same key
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_registry_returns_same_limiter_for_same_key():
    """get_or_create() with the same key returns the same instance."""

    def _given_rate_limiter_registry():
        return RateLimiterRegistry

    def _when_limiter_requested_twice_with_same_key(registry):
        limiter_a = registry.get_or_create("service_a", max_requests=10, period=60)
        limiter_b = registry.get_or_create("service_a", max_requests=10, period=60)
        return limiter_a, limiter_b

    def _then_same_instance_returned(limiter_a, limiter_b):
        assert limiter_a is limiter_b

    registry = _given_rate_limiter_registry()
    limiter_a, limiter_b = _when_limiter_requested_twice_with_same_key(registry)
    _then_same_instance_returned(limiter_a, limiter_b)


# ---------------------------------------------------------------------------
# Scenario: Registry creates distinct rate limiters for different keys
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_registry_creates_distinct_limiters_for_different_keys():
    """get_or_create() with different keys returns different instances."""

    def _given_rate_limiter_registry():
        return RateLimiterRegistry

    def _when_limiters_requested_with_different_keys(registry):
        limiter_a = registry.get_or_create("service_a", max_requests=10, period=60)
        limiter_b = registry.get_or_create("service_b", max_requests=10, period=60)
        return limiter_a, limiter_b

    def _then_different_instances_returned(limiter_a, limiter_b):
        assert limiter_a is not limiter_b

    registry = _given_rate_limiter_registry()
    limiter_a, limiter_b = _when_limiters_requested_with_different_keys(registry)
    _then_different_instances_returned(limiter_a, limiter_b)
