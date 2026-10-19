from datetime import datetime, timedelta, timezone

import pytest
from connector.import_filter import (
    build_cel_filter,
    normalize_min_bucket,
    parse_iso_duration,
    window_start,
)


def test_parse_iso_duration_basic():
    assert parse_iso_duration("P1D") == timedelta(days=1)
    assert parse_iso_duration("PT6H") == timedelta(hours=6)
    assert parse_iso_duration("PT5M") == timedelta(minutes=5)
    assert parse_iso_duration("P1DT12H") == timedelta(days=1, hours=12)


def test_parse_iso_duration_falls_back_on_garbage():
    assert parse_iso_duration("") == timedelta(days=1)
    assert parse_iso_duration("notaduration") == timedelta(days=1)
    assert parse_iso_duration("P1Y") == timedelta(
        days=1
    )  # years not supported, fall back


def test_normalize_min_bucket_default_is_high_or_higher():
    assert normalize_min_bucket(None) == [
        "PROBABILITY_HIGH",
        "PROBABILITY_VERY_HIGH",
    ]
    assert normalize_min_bucket("") == [
        "PROBABILITY_HIGH",
        "PROBABILITY_VERY_HIGH",
    ]


def test_normalize_min_bucket_low_includes_all():
    assert normalize_min_bucket("LOW") == [
        "PROBABILITY_LOW",
        "PROBABILITY_MEDIUM",
        "PROBABILITY_HIGH",
        "PROBABILITY_VERY_HIGH",
    ]


def test_normalize_min_bucket_accepts_prefixed():
    assert normalize_min_bucket("PROBABILITY_MEDIUM") == [
        "PROBABILITY_MEDIUM",
        "PROBABILITY_HIGH",
        "PROBABILITY_VERY_HIGH",
    ]


def test_normalize_min_bucket_unknown_falls_back_to_high():
    assert normalize_min_bucket("ABSURD") == [
        "PROBABILITY_HIGH",
        "PROBABILITY_VERY_HIGH",
    ]


def test_build_cel_filter_basic_shape():
    cutoff = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
    f = build_cel_filter(cutoff=cutoff)
    assert "mal_eval.malicious==true" in f
    assert 'object.global_first_seen_time >= "2026-05-01T12:00:00.000Z"' in f


def test_build_cel_filter_is_only_the_malicious_flag_and_time_cutoff():
    # Bucket filtering is client-side (server-side `probability_bucket in
    # [...]` returns 500) and there is no per-environment CEL field yet, so
    # the filter takes only the cutoff.
    assert build_cel_filter(cutoff=None) == "mal_eval.malicious==true"
    with pytest.raises(TypeError):
        build_cel_filter(cutoff=None, min_bucket="HIGH")


def test_window_start_uses_the_watermark():
    watermark = datetime(2026, 5, 5, tzinfo=timezone.utc)
    now = datetime(2026, 5, 6, tzinfo=timezone.utc)
    assert window_start(watermark, timedelta(days=1), now) == watermark


def test_window_start_treats_a_naive_watermark_as_utc():
    now = datetime(2026, 5, 6, tzinfo=timezone.utc)
    assert window_start(datetime(2026, 5, 5), timedelta(days=1), now) == datetime(
        2026, 5, 5, tzinfo=timezone.utc
    )


def test_window_start_falls_back_to_now_minus_window():
    now = datetime(2026, 5, 6, tzinfo=timezone.utc)
    assert window_start(None, timedelta(days=2), now) == now - timedelta(days=2)


def test_build_cel_filter_bounds_the_window_and_normalises_to_utc():
    cutoff = datetime(2026, 5, 4, 1, 0, tzinfo=timezone(timedelta(hours=1)))
    end = datetime(2026, 5, 5, tzinfo=timezone.utc)
    assert build_cel_filter(cutoff=cutoff, window_end=end) == (
        "mal_eval.malicious==true"
        ' && object.global_first_seen_time >= "2026-05-04T00:00:00.000Z"'
        ' && object.global_first_seen_time < "2026-05-05T00:00:00.000Z"'
    )
    # Naive datetimes are UTC.
    assert '>= "2026-05-04T00:00:00.000Z"' in build_cel_filter(
        cutoff=datetime(2026, 5, 4), window_end=None
    )
