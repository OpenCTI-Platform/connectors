"""RED tests for Feature: Rate Limit Sliding Window.

Tests that the sliding window correctly blocks and releases capacity
as requests age out.

All tests MUST fail with ImportError until the implementation exists.
"""

import asyncio
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
    RateLimiterRegistry.clear()
    yield
    RateLimiterRegistry.clear()


# ---------------------------------------------------------------------------
# Scenario: Full window blocks new requests until the oldest expires
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_full_window_blocks_until_oldest_expires():
    """4th request with max_requests=3 blocks until the oldest ages out."""

    async def _given_rate_limiter_with_3_slots_consumed():
        limiter = TokenBucketRateLimiter(max_requests=3, period=0.5)
        await limiter.acquire()
        await limiter.acquire()
        await limiter.acquire()
        return limiter

    async def _when_4th_slot_acquired(limiter):
        start = time.monotonic()
        await limiter.acquire()
        elapsed = time.monotonic() - start
        return elapsed

    def _then_slot_granted_after_oldest_ages_out(elapsed):
        assert elapsed >= 0.3, "Should block until oldest request expires"

    limiter = await _given_rate_limiter_with_3_slots_consumed()
    elapsed = await _when_4th_slot_acquired(limiter)
    _then_slot_granted_after_oldest_ages_out(elapsed)


# ---------------------------------------------------------------------------
# Scenario: Expired requests free capacity immediately
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_expired_requests_free_capacity_immediately():
    """After period elapses, all previous slots have expired — new slot instant."""

    async def _given_3_slots_acquired_more_than_1_second_ago():
        limiter = TokenBucketRateLimiter(max_requests=3, period=0.5)
        await limiter.acquire()
        await limiter.acquire()
        await limiter.acquire()
        await asyncio.sleep(0.6)  # wait for all to expire
        return limiter

    async def _when_new_slot_acquired(limiter):
        start = time.monotonic()
        await limiter.acquire()
        elapsed = time.monotonic() - start
        return elapsed

    def _then_slot_granted_immediately(elapsed):
        assert elapsed < 0.1, "Expired requests should free capacity instantly"

    limiter = await _given_3_slots_acquired_more_than_1_second_ago()
    elapsed = await _when_new_slot_acquired(limiter)
    _then_slot_granted_immediately(elapsed)
