"""Tests for the connector utility helpers."""

import re
from datetime import datetime, timezone

from connector.utils import normalize_timestamp

ISO_Z_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class TestNormalizeTimestamp:
    """normalize_timestamp must always return a STIX-compatible Z-suffixed string."""

    def test_empty_value_returns_now(self):
        result = normalize_timestamp(None)
        assert ISO_Z_PATTERN.match(result)

    def test_empty_string_returns_now(self):
        result = normalize_timestamp("")
        assert ISO_Z_PATTERN.match(result)

    def test_epoch_seconds_int(self):
        # 2021-01-01T00:00:00Z
        assert normalize_timestamp(1609459200) == "2021-01-01T00:00:00Z"

    def test_epoch_milliseconds_int(self):
        # 1609459200000 ms -> same instant as 1609459200 s
        assert normalize_timestamp(1609459200000) == "2021-01-01T00:00:00Z"

    def test_epoch_float(self):
        assert normalize_timestamp(1609459200.0) == "2021-01-01T00:00:00Z"

    def test_non_string_non_number_returns_now(self):
        result = normalize_timestamp(["not", "a", "timestamp"])
        assert ISO_Z_PATTERN.match(result)

    def test_numeric_string_epoch_seconds(self):
        assert normalize_timestamp("1609459200") == "2021-01-01T00:00:00Z"

    def test_numeric_string_epoch_milliseconds(self):
        assert normalize_timestamp("1609459200000") == "2021-01-01T00:00:00Z"

    def test_ddmmyyyy_12h_am_pm(self):
        assert normalize_timestamp("04-03-2026 08:52:59 AM") == "2026-03-04T08:52:59Z"

    def test_ddmmyyyy_24h(self):
        assert normalize_timestamp("04-03-2026 18:29:05") == "2026-03-04T18:29:05Z"

    def test_iso8601_with_z(self):
        assert normalize_timestamp("2026-03-04T18:00:00Z") == "2026-03-04T18:00:00Z"

    def test_iso8601_without_timezone(self):
        assert normalize_timestamp("2026-03-04T18:00:00") == "2026-03-04T18:00:00Z"

    def test_iso8601_with_offset(self):
        # +02:00 offset must be converted to UTC, not just stamped with "Z":
        # 18:00+02:00 is 16:00Z.
        assert (
            normalize_timestamp("2026-03-04T18:00:00+02:00") == "2026-03-04T16:00:00Z"
        )

    def test_iso8601_with_negative_offset(self):
        # -05:00 offset -> UTC is five hours ahead of the local wall clock.
        assert (
            normalize_timestamp("2026-03-04T18:00:00-05:00") == "2026-03-04T23:00:00Z"
        )

    def test_epoch_zero_is_unix_epoch(self):
        # 0 is a valid epoch (1970-01-01T00:00:00Z), not a missing value.
        assert normalize_timestamp(0) == "1970-01-01T00:00:00Z"

    def test_huge_epoch_int_falls_back_to_now(self):
        # An out-of-range epoch must not raise OverflowError/OSError; it falls
        # back to a valid "now" timestamp like the other branches.
        assert ISO_Z_PATTERN.match(normalize_timestamp(10**20))

    def test_huge_epoch_string_falls_back_to_now(self):
        assert ISO_Z_PATTERN.match(normalize_timestamp(str(10**20)))

    def test_invalid_string_returns_now(self):
        result = normalize_timestamp("definitely not a date")
        assert ISO_Z_PATTERN.match(result)

    def test_now_fallback_is_utc(self):
        before = datetime.now(timezone.utc).replace(microsecond=0)
        result = normalize_timestamp(None)
        parsed = datetime.strptime(result, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        assert abs((parsed - before).total_seconds()) < 5
