# pragma: no cover
# type: ignore
"""Tests of the hunt time helpers."""

from datetime import datetime, timezone

import pytest
from connectors_sdk.connectors.internal_hunt import (
    HuntTimeoutError,
    RunDeadline,
    parse_timestamp,
)


class _Clock:
    def __init__(self):
        self.now = 100.0
        self.slept = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


def test_run_deadline_bounds_requests_and_sleeps():
    # Given a 10 seconds deadline
    clock = _Clock()
    deadline = RunDeadline(10, clock=clock, sleeper=clock.sleep)

    # When/Then the remaining time bounds the requests and the sleeps
    assert deadline.remaining() == 10
    assert deadline.request_timeout(maximum=4) == 4
    deadline.sleep(3)
    assert deadline.request_timeout() == 7
    deadline.check("job")
    deadline.sleep(30)
    assert clock.slept == [3, 7]
    assert deadline.expired() is True
    with pytest.raises(HuntTimeoutError, match="Splunk job did not complete"):
        deadline.check("Splunk job")


def test_run_deadline_never_gives_a_request_more_time_than_is_left():
    # Given a deadline with a fraction of a second left
    clock = _Clock()
    deadline = RunDeadline(10, clock=clock, sleeper=clock.sleep)
    clock.now += 9.99

    # When/Then the request timeout is the time left, not a floor of one second
    assert deadline.request_timeout() == pytest.approx(0.01)

    # And no request is sent once the deadline is reached
    clock.now += 1
    with pytest.raises(HuntTimeoutError, match="The token request did not complete"):
        deadline.request_timeout(operation="The token request")


def test_run_deadline_uses_the_monotonic_clock_by_default():
    # Given/When a real deadline is created
    deadline = RunDeadline(60)

    # Then time is left
    assert 0 < deadline.remaining() <= 60
    deadline.sleep(0)


@pytest.mark.parametrize(
    "value, expected",
    [
        ("2026-10-03T10:00:00Z", datetime(2026, 10, 3, 10, tzinfo=timezone.utc)),
        (
            "2026-10-03T12:00:00.1234567+02:00",
            datetime(2026, 10, 3, 10, 0, 0, 123456, tzinfo=timezone.utc),
        ),
        ("2026-10-03 10:00:00", datetime(2026, 10, 3, 10, tzinfo=timezone.utc)),
        (1791021600, datetime(2026, 10, 3, 10, tzinfo=timezone.utc)),
        (1791021600000, datetime(2026, 10, 3, 10, tzinfo=timezone.utc)),
        ("1791021600000", datetime(2026, 10, 3, 10, tzinfo=timezone.utc)),
        (1791021600.5, datetime(2026, 10, 3, 10, 0, 0, 500000, tzinfo=timezone.utc)),
        (datetime(2026, 10, 3, 10), datetime(2026, 10, 3, 10, tzinfo=timezone.utc)),
        (
            datetime(2026, 10, 3, 10, tzinfo=timezone.utc),
            datetime(2026, 10, 3, 10, tzinfo=timezone.utc),
        ),
        (None, None),
        (True, None),
        ("", None),
        ("not a date", None),
        ([1], None),
        (10**20, None),
    ],
)
def test_parse_timestamp(value, expected):
    # Given/When/Then every supported time format is parsed to an aware datetime
    assert parse_timestamp(value) == expected
