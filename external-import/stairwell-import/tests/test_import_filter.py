from datetime import datetime, timedelta, timezone

import pytest
from connector.import_filter import (
    allowed_buckets,
    build_cel_filter,
    window_start,
)


@pytest.mark.parametrize(
    ("min_bucket", "want"),
    [
        ("LOW", ["LOW", "MEDIUM", "HIGH", "VERY_HIGH"]),
        ("MEDIUM", ["MEDIUM", "HIGH", "VERY_HIGH"]),
        ("HIGH", ["HIGH", "VERY_HIGH"]),
        ("VERY_HIGH", ["VERY_HIGH"]),
    ],
)
def test_allowed_buckets_are_the_minimum_and_above(min_bucket, want):
    assert allowed_buckets(min_bucket) == [f"PROBABILITY_{b}" for b in want]


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
