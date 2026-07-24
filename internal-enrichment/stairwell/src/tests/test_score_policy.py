from connector.stairwell.score import (
    PROB_SCORE_MAP,
    monotonic_score,
    score_for_bucket,
)


def test_score_for_bucket_known_buckets():
    assert score_for_bucket("PROBABILITY_VERY_HIGH") == 90
    assert score_for_bucket("PROBABILITY_HIGH") == 75
    assert score_for_bucket("PROBABILITY_MEDIUM") == 50
    assert score_for_bucket("PROBABILITY_LOW") == 25


def test_score_for_bucket_unknown_or_missing():
    assert score_for_bucket(None) is None
    assert score_for_bucket("") is None
    assert score_for_bucket("HIGH") is None  # unprefixed should not match
    assert score_for_bucket("PROBABILITY_UNKNOWN") is None


def test_monotonic_proposed_higher_wins():
    assert monotonic_score(50, 75) == 75


def test_monotonic_proposed_lower_loses():
    assert monotonic_score(90, 50) == 90


def test_monotonic_no_current_takes_proposed():
    assert monotonic_score(None, 75) == 75


def test_monotonic_no_proposed_keeps_current():
    assert monotonic_score(50, None) == 50


def test_monotonic_both_none():
    assert monotonic_score(None, None) is None


def test_score_map_keys_are_prefixed():
    # Guard against the parent-plan/production drift where unprefixed names
    # were proposed; the real API uses PROBABILITY_* prefix.
    for key in PROB_SCORE_MAP:
        assert key.startswith("PROBABILITY_")
