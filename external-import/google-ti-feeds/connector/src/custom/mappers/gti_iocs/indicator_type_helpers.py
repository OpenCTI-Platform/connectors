"""Shared helpers for extracting indicator types from GTI assessment data."""

from typing import Any

from connector.src.stix.v21.models.ovs.indicator_type_ov_enums import IndicatorTypeOV


def indicator_types_from_verdict(gti_assessment: Any) -> list[IndicatorTypeOV]:
    """Extract indicator types from a GTI assessment verdict.

    Accepts any GTI assessment model that exposes ``verdict.value``.
    Returns an empty list when no classification is available, ensuring the
    downstream field is omitted rather than defaulting to a placeholder.

    Args:
        gti_assessment: A GTI assessment object (may be ``None``).

    Returns:
        list[IndicatorTypeOV]: Singleton list with the verdict,
        or empty list when the verdict is absent.

    """
    if gti_assessment is None:
        return []
    if not (gti_assessment.verdict and gti_assessment.verdict.value):
        return []
    return [IndicatorTypeOV(gti_assessment.verdict.value)]
