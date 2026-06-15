from doppel.utils import parse_iso_datetime


def test_parse_iso_datetime_normalizes_z_suffix():
    dt = parse_iso_datetime("2026-06-11T09:00:00Z")
    assert dt is not None
    # Z must be normalized to a UTC offset so the datetime is timezone-aware.
    assert dt.tzinfo is not None
    assert dt.utcoffset().total_seconds() == 0


def test_parse_iso_datetime_handles_explicit_offset():
    dt = parse_iso_datetime("2026-06-11T09:00:00+00:00")
    assert dt is not None
    assert dt.tzinfo is not None


def test_parse_iso_datetime_returns_none_for_missing_or_invalid():
    assert parse_iso_datetime(None) is None
    assert parse_iso_datetime("") is None
    assert parse_iso_datetime("not-a-date") is None
    assert parse_iso_datetime(12345) is None
