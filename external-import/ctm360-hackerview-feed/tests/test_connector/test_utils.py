"""Tests for the connector timestamp helper."""

import re

from connector.utils import normalize_timestamp

ISO_Z_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class TestNormalizeTimestamp:
    def test_empty_returns_now(self):
        assert ISO_Z_PATTERN.match(normalize_timestamp(None))
        assert ISO_Z_PATTERN.match(normalize_timestamp(""))

    def test_epoch_seconds(self):
        assert normalize_timestamp(1609459200) == "2021-01-01T00:00:00Z"

    def test_epoch_milliseconds(self):
        assert normalize_timestamp(1609459200000) == "2021-01-01T00:00:00Z"

    def test_numeric_string_epoch(self):
        assert normalize_timestamp("1609459200") == "2021-01-01T00:00:00Z"

    def test_numeric_string_epoch_milliseconds(self):
        assert normalize_timestamp("1609459200000") == "2021-01-01T00:00:00Z"

    def test_non_string_non_number_returns_now(self):
        assert ISO_Z_PATTERN.match(normalize_timestamp(["nope"]))

    def test_ddmmyyyy_hms(self):
        assert normalize_timestamp("02-03-2026 17:32:52") == "2026-03-02T17:32:52Z"

    def test_iso_with_z(self):
        assert normalize_timestamp("2026-03-04T18:00:00Z") == "2026-03-04T18:00:00Z"

    def test_iso_naive(self):
        assert normalize_timestamp("2026-03-04T18:00:00") == "2026-03-04T18:00:00Z"

    def test_iso_non_utc_offset_converted_to_utc(self):
        assert (
            normalize_timestamp("2026-03-04T20:00:00+03:00") == "2026-03-04T17:00:00Z"
        )

    def test_invalid_returns_now(self):
        assert ISO_Z_PATTERN.match(normalize_timestamp("definitely not a date"))

    def test_huge_epoch_int_falls_back_to_now(self):
        # An out-of-range epoch must not raise OverflowError/OSError; it falls
        # back to a valid "now" timestamp like the other branches.
        assert ISO_Z_PATTERN.match(normalize_timestamp(10**20))

    def test_huge_epoch_string_falls_back_to_now(self):
        assert ISO_Z_PATTERN.match(normalize_timestamp(str(10**20)))
