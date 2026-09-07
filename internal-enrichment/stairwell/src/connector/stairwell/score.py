from __future__ import annotations

PROB_SCORE_MAP: dict[str, int] = {
    "PROBABILITY_VERY_HIGH": 90,
    "PROBABILITY_HIGH": 75,
    "PROBABILITY_MEDIUM": 50,
    "PROBABILITY_LOW": 25,
}


def score_for_bucket(bucket: str | None) -> int | None:
    if not bucket:
        return None
    return PROB_SCORE_MAP.get(bucket)


def monotonic_score(current: int | None, proposed: int | None) -> int | None:
    if proposed is None:
        return current
    if current is None:
        return proposed
    return proposed if proposed > current else current
