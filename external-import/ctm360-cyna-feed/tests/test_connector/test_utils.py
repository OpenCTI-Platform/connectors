"""Tests for the connector utility helpers."""

import re

from connector.utils import extract_cves, is_newer_than, normalize_timestamp

ISO_Z_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class TestNormalizeTimestamp:
    def test_empty_returns_now(self):
        assert ISO_Z_PATTERN.match(normalize_timestamp(None))
        assert ISO_Z_PATTERN.match(normalize_timestamp(""))

    def test_epoch_seconds(self):
        assert normalize_timestamp(1609459200) == "2021-01-01T00:00:00Z"

    def test_epoch_zero_is_unix_epoch_not_now(self):
        # 0 is a valid Unix epoch and must not be treated as "missing".
        assert normalize_timestamp(0) == "1970-01-01T00:00:00Z"
        assert normalize_timestamp(0.0) == "1970-01-01T00:00:00Z"
        assert normalize_timestamp("0") == "1970-01-01T00:00:00Z"

    def test_epoch_milliseconds(self):
        assert normalize_timestamp(1609459200000) == "2021-01-01T00:00:00Z"

    def test_numeric_string_epoch(self):
        assert normalize_timestamp("1609459200") == "2021-01-01T00:00:00Z"

    def test_numeric_string_epoch_milliseconds(self):
        assert normalize_timestamp("1609459200000") == "2021-01-01T00:00:00Z"

    def test_non_string_non_number_returns_now(self):
        assert ISO_Z_PATTERN.match(normalize_timestamp(["nope"]))

    def test_iso_with_z(self):
        assert normalize_timestamp("2026-03-04T18:00:00Z") == "2026-03-04T18:00:00Z"

    def test_iso_naive(self):
        assert normalize_timestamp("2026-03-04T18:00:00") == "2026-03-04T18:00:00Z"

    def test_space_separated_datetime(self):
        assert normalize_timestamp("2026-03-04 20:50:49") == "2026-03-04T20:50:49Z"

    def test_iso_with_non_utc_offset_is_converted_to_utc(self):
        # 20:00+03:00 must become 17:00Z (converted), not 20:00Z.
        assert (
            normalize_timestamp("2026-03-04T20:00:00+03:00") == "2026-03-04T17:00:00Z"
        )

    def test_date_only_formats(self):
        assert normalize_timestamp("2026-03-04") == "2026-03-04T00:00:00Z"
        assert normalize_timestamp("04/03/2026") == "2026-03-04T00:00:00Z"

    def test_invalid_returns_now(self):
        assert ISO_Z_PATTERN.match(normalize_timestamp("not a date at all"))

    def test_out_of_range_epoch_int_falls_back_to_now(self):
        # A wildly out-of-range epoch raises OverflowError/OSError in
        # datetime.fromtimestamp(); it must fall back to now, not crash.
        assert ISO_Z_PATTERN.match(normalize_timestamp(10**20))

    def test_out_of_range_epoch_string_falls_back_to_now(self):
        assert ISO_Z_PATTERN.match(normalize_timestamp(str(10**20)))


class TestExtractCves:
    def test_empty(self):
        assert extract_cves("") == []
        assert extract_cves(None) == []

    def test_single(self):
        assert extract_cves("Patch for CVE-2024-12345 now") == ["CVE-2024-12345"]

    def test_case_insensitive_and_uppercased(self):
        assert extract_cves("cve-2024-0001 issue") == ["CVE-2024-0001"]

    def test_dedup_preserves_order(self):
        text = "CVE-2024-0002 and CVE-2024-0001 and cve-2024-0002 again"
        assert extract_cves(text) == ["CVE-2024-0002", "CVE-2024-0001"]

    def test_no_match(self):
        assert extract_cves("no identifiers here") == []


class TestIsNewerThan:
    def test_none_values_return_true(self):
        assert is_newer_than(None, "2026-01-01T00:00:00Z") is True
        assert is_newer_than("2026-01-01T00:00:00Z", None) is True

    def test_newer(self):
        assert is_newer_than("2026-02-01T00:00:00Z", "2026-01-01T00:00:00Z") is True

    def test_older(self):
        assert is_newer_than("2025-12-01T00:00:00Z", "2026-01-01T00:00:00Z") is False

    def test_equal_is_not_newer(self):
        ts = "2026-01-01T00:00:00Z"
        assert is_newer_than(ts, ts) is False

    def test_unparseable_returns_bool_without_raising(self):
        # Unparseable inputs must not raise: both normalise to "now" via the
        # datetime.now() fallback, so the helper still returns a real bool.
        result = is_newer_than("garbage", "garbage")
        assert isinstance(result, bool)
