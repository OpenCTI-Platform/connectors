"""Hunter severity → OpenCTI score."""

from __future__ import annotations

import logging

LOGGER = logging.getLogger(__name__)

_SCORES = {
    "high": 90,
    "medium": 60,
    "low": 30,
}
_UNKNOWN = 50


def severity_to_score(severity: str | None) -> int:
    if not severity:
        LOGGER.warning("Hunt missing severity; defaulting score to %d", _UNKNOWN)
        return _UNKNOWN
    score = _SCORES.get(severity.strip().lower())
    if score is None:
        LOGGER.warning(
            "Unknown severity %r; defaulting score to %d", severity, _UNKNOWN
        )
        return _UNKNOWN
    return score
