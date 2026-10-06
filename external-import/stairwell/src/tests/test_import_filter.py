from datetime import datetime, timedelta, timezone

from connector.import_filter import (
    build_cel_filter,
    compute_cutoff,
    normalize_min_bucket,
    parse_iso_duration,
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


def test_build_cel_filter_no_bucket_clause_ever():
    # Server-side `probability_bucket in [...]` returns 500; bucket filtering
    # is done client-side in the runner. CEL must never include it.
    for arg in (None, "LOW", "MEDIUM", "HIGH", "VERY_HIGH"):
        assert "probability_bucket" not in build_cel_filter(cutoff=None, min_bucket=arg)


def test_build_cel_filter_environment_scope_currently_no_op():
    f = build_cel_filter(cutoff=None, scope_environment=True)
    assert "is_seen_in_environment" not in f


def test_compute_cutoff_uses_state_when_present():
    state = {"last_run": "2026-05-05T00:00:00.000Z"}
    cutoff = compute_cutoff(
        state,
        first_run_window=timedelta(days=1),
        now=datetime(2026, 5, 6, tzinfo=timezone.utc),
    )
    assert cutoff == datetime(2026, 5, 5, tzinfo=timezone.utc)


def test_compute_cutoff_falls_back_to_now_minus_window():
    now = datetime(2026, 5, 6, tzinfo=timezone.utc)
    cutoff = compute_cutoff(state=None, first_run_window=timedelta(days=2), now=now)
    assert cutoff == now - timedelta(days=2)


def test_compute_cutoff_handles_malformed_state():
    cutoff = compute_cutoff(
        state={"last_run": "not-a-timestamp"},
        first_run_window=timedelta(hours=6),
        now=datetime(2026, 5, 6, tzinfo=timezone.utc),
    )
    # Malformed → fall back to window
    assert cutoff == datetime(2026, 5, 6, tzinfo=timezone.utc) - timedelta(hours=6)
