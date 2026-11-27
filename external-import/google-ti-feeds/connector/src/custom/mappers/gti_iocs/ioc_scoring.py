"""Score and verdict helpers for GTI IOCs (`indicator_scoring`, `indicator_min_verdict`)."""

from typing import Any

VERDICT_BASE_SCORES = {
    "VERDICT_MALICIOUS": 80,
    "VERDICT_SUSPICIOUS": 60,
    "VERDICT_UNDETECTED": 20,
    "VERDICT_BENIGN": 0,
}
SEVERITY_BONUSES = {
    "SEVERITY_HIGH": 10,
    "SEVERITY_MEDIUM": 5,
}
# Below 100 so a verdict-only score never claims full certainty.
GTI_DERIVED_MAX_SCORE = 95
SUSPICIOUS_DETECTION_WEIGHT = 0.5


# Fallbacks when the threat score is missing. mandiant_confidence_score is deprecated by GTI.
CONFIDENCE_SCORE_FIELDS = ("gti_confidence_score", "mandiant_confidence_score")


def score_from_threat_score(gti_assessment: Any) -> int | None:
    """Return the GTI threat score, falling back to the GTI then Mandiant confidence score."""
    if gti_assessment is None:
        return None
    threat_score = getattr(gti_assessment, "threat_score", None)
    if threat_score is not None and threat_score.value is not None:
        return int(threat_score.value)
    factors = getattr(gti_assessment, "contributing_factors", None)
    for field in CONFIDENCE_SCORE_FIELDS:
        confidence = getattr(factors, field, None)
        if confidence is not None:
            return int(confidence)
    return None


def score_from_gti_verdict(gti_assessment: Any) -> int | None:
    """Map the GTI verdict and severity to a score.

    Unknown or missing verdicts return None.
    """
    verdict = getattr(getattr(gti_assessment, "verdict", None), "value", None)
    base = VERDICT_BASE_SCORES.get((verdict or "").upper())
    if base is None:
        return None
    severity = getattr(getattr(gti_assessment, "severity", None), "value", None)
    bonus = SEVERITY_BONUSES.get((severity or "").upper(), 0)
    return min(base + bonus, GTI_DERIVED_MAX_SCORE)


def score_from_detection_stats(last_analysis_stats: Any) -> int | None:
    """Return the weighted share of engines flagging the IOC, from 0 to 100.

    Malicious counts fully, suspicious counts half, harmless and undetected
    count as clean. Timeouts are ignored. No stats or no verdicts return None.
    """
    if last_analysis_stats is None:
        return None
    malicious = last_analysis_stats.malicious or 0
    suspicious = last_analysis_stats.suspicious or 0
    harmless = last_analysis_stats.harmless or 0
    undetected = last_analysis_stats.undetected or 0
    total = malicious + suspicious + harmless + undetected
    if total == 0:
        return None
    flagged = malicious + suspicious * SUSPICIOUS_DETECTION_WEIGHT
    return round(flagged / total * 100)


def compute_ioc_score(attributes: Any, strategy: str = "threat_score") -> int | None:
    """Compute an IOC score with the given strategy.

    Falls back to `threat_score` when the selected strategy has no data.

    Args:
        attributes: GTI IOC attributes exposing `gti_assessment` and, for
            collection IOCs, `last_analysis_stats`.
        strategy: One of `threat_score`, `gti_derived`, `average_detection`.

    Returns:
        The score from 0 to 100, or None when no source is available.

    """
    if attributes is None:
        return None
    gti_assessment = getattr(attributes, "gti_assessment", None)

    score = None
    if strategy == "gti_derived":
        score = score_from_gti_verdict(gti_assessment)
    elif strategy == "average_detection":
        score = score_from_detection_stats(
            getattr(attributes, "last_analysis_stats", None)
        )

    if score is None:
        score = score_from_threat_score(gti_assessment)
    return score


# Verdicts creating an indicator, by `indicator_min_verdict` value. Other values: no filter.
INDICATOR_VERDICTS = {
    "suspicious": frozenset({"VERDICT_SUSPICIOUS", "VERDICT_MALICIOUS"}),
    "malicious": frozenset({"VERDICT_MALICIOUS"}),
}


def meets_min_verdict(attributes: Any, min_verdict: str) -> bool:
    """Return whether the GTI verdict of an IOC is at least `min_verdict`.

    With 'suspicious' or 'malicious', an IOC without a verdict does not qualify.

    Args:
        attributes: GTI IOC attributes exposing `gti_assessment`.
        min_verdict: One of `any`, `suspicious`, `malicious`.

    Returns:
        True when the IOC qualifies for an indicator.

    """
    accepted = INDICATOR_VERDICTS.get(min_verdict)
    if accepted is None:
        return True
    gti_assessment = getattr(attributes, "gti_assessment", None)
    verdict = getattr(getattr(gti_assessment, "verdict", None), "value", None)
    return (verdict or "").upper() in accepted
