"""Tests for AsyncRateLimiter concurrency correctness.

Validates that:
- The sliding-window algorithm enforces the request cap.
- Concurrent callers are properly serialised by the internal lock.
- ``reset_lock()`` rebinds the lock for cross-asyncio.run() safety while
  keeping the request history so the window stays continuous.
"""

import asyncio
import time

import src.services.utils.rate_limiter as rl_module
from src.services.utils.rate_limiter import (
    NVD_MAX_REQUESTS,
    AsyncRateLimiter,
)


async def test_acquire_within_limit_does_not_block():
    """Acquiring fewer slots than the max should return instantly."""
    limiter = AsyncRateLimiter()
    t0 = time.monotonic()

    for _ in range(NVD_MAX_REQUESTS):
        await limiter.acquire()

    elapsed = time.monotonic() - t0
    assert elapsed < 1.0, f"Expected no blocking, took {elapsed:.2f}s"


async def test_acquire_over_limit_blocks():
    """The (max+1)-th acquire must block until the window slides."""
    limiter = AsyncRateLimiter()

    for _ in range(NVD_MAX_REQUESTS):
        await limiter.acquire()

    # Next acquire should block; verify it doesn't complete within 0.1s.
    acquired = asyncio.Event()

    async def try_acquire():
        await limiter.acquire()
        acquired.set()

    task = asyncio.create_task(try_acquire())

    await asyncio.sleep(0.15)
    assert not acquired.is_set(), "Should have blocked but did not"

    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


async def test_concurrent_acquires_respect_limit():
    """Launch many concurrent acquire() calls; verify at most
    NVD_MAX_REQUESTS succeed within the window."""
    limiter = AsyncRateLimiter()
    acquired_times: list[float] = []
    lock = asyncio.Lock()

    async def worker():
        await limiter.acquire()
        async with lock:
            acquired_times.append(time.monotonic())

    num_workers = NVD_MAX_REQUESTS + 10
    tasks = [asyncio.create_task(worker()) for _ in range(num_workers)]

    # Give enough time for the first batch to complete but not the overflow
    await asyncio.sleep(0.3)

    immediate = [t for t in acquired_times if t - acquired_times[0] < 0.5]
    assert (
        len(immediate) == NVD_MAX_REQUESTS
    ), f"Expected {NVD_MAX_REQUESTS} immediate acquires, got {len(immediate)}"

    for task in tasks:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


async def test_reset_lock_preserves_window_history():
    """reset_lock() must keep the request history so a full budget is NOT
    freed at a chunk boundary; the (max+1)-th acquire still blocks."""
    limiter = AsyncRateLimiter()

    for _ in range(NVD_MAX_REQUESTS):
        await limiter.acquire()

    limiter.reset_lock()

    # Timestamps survive the reset, so the window is still full.
    assert len(limiter._timestamps) == NVD_MAX_REQUESTS

    acquired = asyncio.Event()

    async def try_acquire():
        await limiter.acquire()
        acquired.set()

    task = asyncio.create_task(try_acquire())
    await asyncio.sleep(0.15)
    assert not acquired.is_set(), "reset_lock() must not free the window budget"

    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


async def test_reset_lock_invalidates_lock():
    """reset_lock() must set _lock to None so a fresh Lock is created
    in the next event loop (cross-asyncio.run safety)."""
    limiter = AsyncRateLimiter()
    await limiter.acquire()

    old_lock = limiter._lock
    limiter.reset_lock()

    assert limiter._lock is None

    # A new acquire should create a new lock
    await limiter.acquire()
    assert limiter._lock is not old_lock


async def test_sliding_window_releases_slots():
    """Slots should free up after the window interval passes."""
    # Use a patched short interval for speed

    original_interval = rl_module.NVD_INTERVAL_SECONDS
    original_max = rl_module.NVD_MAX_REQUESTS
    rl_module.NVD_INTERVAL_SECONDS = 0.3
    rl_module.NVD_MAX_REQUESTS = 3

    try:
        limiter = AsyncRateLimiter()

        # Fill the window
        for _ in range(3):
            await limiter.acquire()

        # Wait for window to slide
        await asyncio.sleep(0.4)

        # Should be able to acquire again without blocking
        t0 = time.monotonic()
        await limiter.acquire()
        elapsed = time.monotonic() - t0
        assert (
            elapsed < 0.2
        ), f"Expected slot freed after window slide, took {elapsed:.2f}s"
    finally:
        rl_module.NVD_INTERVAL_SECONDS = original_interval
        rl_module.NVD_MAX_REQUESTS = original_max
