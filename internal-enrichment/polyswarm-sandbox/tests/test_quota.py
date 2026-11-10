"""Tests for the read-only account quota visibility."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from connector import quota as quota_module
from connector.quota import (
    QuotaMonitor,
    is_quota_exhausted_error,
    parse_account_features,
)
from polyswarm_api import exceptions as polyswarm_exceptions


def _feature(tag, base_uses=0, remaining_uses=0, value=True):
    # Shape of the entries AccountFeatures.features holds (polyswarm-api resources)
    return {
        "base_uses": base_uses,
        "name": f"{tag} feature",
        "remaining_uses": remaining_uses,
        "tag": tag,
        "value": value,
        "overage": 0,
        "backing_feature": None,
    }


def _account(limit=0, remaining=0, features=None, **extra):
    # Shape of AccountFeatures (GET /public/accounts); fixture values only
    values = {
        "account_number": "000000000000",
        "account_plan_name": "Example Plan",
        "plan_period_start": "2026-01-01T00:00:00+00:00",
        "plan_period_end": "2027-01-01T00:00:00+00:00",
        "window_start": "2026-11-01T00:00:00+00:00",
        "window_end": "2026-12-01T00:00:00+00:00",
        "daily_api_limit": limit,
        "daily_api_remaining": remaining,
        "is_trial": False,
        "is_trial_expired": False,
        "features": features if features is not None else [],
    }
    values.update(extra)
    return SimpleNamespace(**values)


class FakeLogger:
    def __init__(self):
        self.records = []

    def info(self, message, *_args):
        self.records.append(("info", message))

    def warning(self, message, *_args):
        self.records.append(("warning", message))

    def of(self, level):
        return [m for lvl, m in self.records if lvl == level]


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def _monitor(api, warn_below=100):
    logger, clock = FakeLogger(), FakeClock()
    return QuotaMonitor(api, logger, warn_below=warn_below, clock=clock), logger, clock


class TestParse:
    def test_internal_plan_is_unlimited(self):
        # Measured: limit 0 and remaining 0 with every feature enabled, no cap
        status = parse_account_features(
            _account(features=[_feature("sandbox_request"), _feature("live_hunt")])
        )
        assert status.daily_unlimited is True
        assert status.daily_exhausted is False
        assert all(f.unlimited for f in status.features)
        assert status.low_items(100) == []

    def test_capped_plan_with_quota_left(self):
        status = parse_account_features(_account(limit=1000, remaining=640))
        assert status.daily_unlimited is False
        assert status.daily_exhausted is False
        assert status.daily_text() == "daily API calls remaining 640 of 1000"

    def test_capped_plan_exhausted(self):
        status = parse_account_features(_account(limit=1000, remaining=0))
        assert status.daily_exhausted is True
        assert status.low_items(100) == ["daily API calls (0 remaining)"]

    def test_only_sandbox_and_hunt_features_are_kept(self):
        status = parse_account_features(
            _account(
                features=[
                    _feature("hash_search"),
                    _feature("max_artifact_size", 512000000, 512000000),
                    _feature("sandbox_request", 50, 3),
                    _feature("historical_hunt", 10, 10, value=False),
                ]
            )
        )
        assert [f.tag for f in status.features] == [
            "sandbox_request",
            "historical_hunt",
        ]
        sandbox, hunt = status.features
        assert (sandbox.limit, sandbox.remaining) == (50, 3)
        assert sandbox.describe() == "sandbox_request: 3 of 50 remaining"
        assert hunt.enabled is False
        assert hunt.describe() == "historical_hunt: not on this plan"
        # A feature that is not on the plan is never reported as low
        assert status.low_items(100) == ["sandbox_request (3 remaining)"]

    def test_missing_fields_do_not_raise(self):
        status = parse_account_features(SimpleNamespace())
        assert status.plan_name is None
        assert status.daily_limit is None
        assert status.daily_text() == "daily API quota not reported"
        assert status.low_items(100) == []

    def test_note_lines_show_remaining_and_window_end(self):
        status = parse_account_features(
            _account(
                limit=500, remaining=0, features=[_feature("sandbox_request", 5, 0)]
            )
        )
        lines = status.note_lines()
        assert "- Plan: Example Plan" in lines
        assert "- Daily API calls remaining: 0 of 500" in lines
        assert "- sandbox_request remaining: 0 of 5" in lines
        assert "- Usage window ends: 2026-12-01T00:00:00+00:00" in lines

    def test_note_lines_unlimited(self):
        lines = parse_account_features(_account()).note_lines()
        assert "- Daily API calls: no cap on this account" in lines

    def test_account_number_is_never_kept(self):
        status = parse_account_features(_account())
        assert "000000000000" not in repr(status)


class TestErrorDetection:
    def test_usage_limits_exception_is_a_quota_error(self):
        error = polyswarm_exceptions.UsageLimitsExceededException(None, "429 limit")
        assert is_quota_exhausted_error(error) is True

    def test_other_request_errors_are_not(self):
        error = polyswarm_exceptions.RequestException(None, "500 server error")
        assert is_quota_exhausted_error(error) is False
        assert is_quota_exhausted_error(ValueError("429")) is False


class TestMonitor:
    def test_startup_read_logs_plan_and_quota(self):
        api = MagicMock()
        api.account_features.return_value = _account(
            limit=1000, remaining=640, features=[_feature("sandbox_request", 500, 300)]
        )
        monitor, logger, _ = _monitor(api)
        monitor.refresh()
        (line,) = logger.of("info")
        assert "plan Example Plan" in line
        assert "daily API calls remaining 640 of 1000" in line
        assert "sandbox_request: 300 of 500 remaining" in line
        assert logger.of("warning") == []
        assert "000000000000" not in line

    def test_reads_at_most_once_an_hour(self):
        api = MagicMock()
        api.account_features.return_value = _account()
        monitor, _, clock = _monitor(api)
        monitor.refresh()
        monitor.refresh()
        clock.now += 3599
        monitor.refresh()
        assert api.account_features.call_count == 1
        clock.now += 2
        monitor.refresh()
        assert api.account_features.call_count == 2

    def test_warns_below_threshold(self):
        api = MagicMock()
        api.account_features.return_value = _account(limit=1000, remaining=40)
        monitor, logger, _ = _monitor(api, warn_below=100)
        monitor.refresh()
        (warning,) = logger.of("warning")
        assert "below 100" in warning
        assert "daily API calls (40 remaining)" in warning

    def test_zero_turns_warnings_off(self):
        api = MagicMock()
        api.account_features.return_value = _account(limit=1000, remaining=0)
        monitor, logger, _ = _monitor(api, warn_below=0)
        monitor.refresh()
        assert logger.of("warning") == []

    def test_unlimited_account_never_warns(self):
        api = MagicMock()
        api.account_features.return_value = _account()
        monitor, logger, _ = _monitor(api, warn_below=100)
        monitor.refresh()
        assert logger.of("warning") == []

    @pytest.mark.parametrize(
        "error",
        [
            ConnectionError("down"),
            polyswarm_exceptions.RequestException(None, "502 bad gateway"),
            polyswarm_exceptions.UsageLimitsExceededException(None, "429"),
            KeyError("daily_api_limit"),
        ],
    )
    def test_read_failure_never_raises(self, error):
        api = MagicMock()
        api.account_features.side_effect = error
        monitor, logger, _ = _monitor(api)
        assert monitor.refresh() is None
        assert monitor.status is None
        (warning,) = logger.of("warning")
        assert "Could not read the account plan and quota" in warning

    def test_failed_read_is_retried_sooner_than_an_hour(self):
        api = MagicMock()
        api.account_features.side_effect = ConnectionError("down")
        monitor, _, clock = _monitor(api)
        monitor.refresh()
        clock.now += quota_module.RETRY_SECONDS - 1
        monitor.refresh()
        assert api.account_features.call_count == 1
        clock.now += 2
        api.account_features.side_effect = None
        api.account_features.return_value = _account()
        assert monitor.refresh() is not None
        assert api.account_features.call_count == 2

    def test_a_broken_logger_does_not_break_the_work(self):
        api = MagicMock()
        api.account_features.return_value = _account()
        logger = MagicMock()
        logger.info.side_effect = RuntimeError("logger down")
        monitor = QuotaMonitor(api, logger)
        assert monitor.refresh() is not None

    def test_failed_read_keeps_the_last_good_status(self):
        api = MagicMock()
        api.account_features.return_value = _account(limit=10, remaining=5)
        monitor, _, clock = _monitor(api)
        monitor.refresh()
        clock.now += 4000
        api.account_features.side_effect = ConnectionError("down")
        assert monitor.refresh().daily_remaining == 5

    def test_exhausted_note_lines_force_a_fresh_read_once_a_minute(self):
        api = MagicMock()
        api.account_features.return_value = _account(limit=500, remaining=0)
        monitor, _, clock = _monitor(api)
        monitor.refresh()
        lines = monitor.exhausted_note_lines()
        assert "- Daily API calls remaining: 0 of 500" in lines
        assert api.account_features.call_count == 2
        monitor.exhausted_note_lines()
        assert api.account_features.call_count == 2
        clock.now += 61
        monitor.exhausted_note_lines()
        assert api.account_features.call_count == 3

    def test_exhausted_note_lines_when_quota_cannot_be_read(self):
        api = MagicMock()
        api.account_features.side_effect = (
            polyswarm_exceptions.UsageLimitsExceededException(None, "429")
        )
        monitor, _, _ = _monitor(api)
        assert monitor.exhausted_note_lines() == [
            "- Remaining quota could not be read from the account"
        ]

    def test_reset_time_unknown_is_stated(self):
        api = MagicMock()
        api.account_features.return_value = _account(
            limit=500, remaining=0, window_end=None
        )
        monitor, _, _ = _monitor(api)
        assert "- Reset time: not reported by the API" in monitor.exhausted_note_lines()
