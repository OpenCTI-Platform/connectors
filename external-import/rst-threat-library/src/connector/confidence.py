"""Confidence-based analyst edit protection for Threat Library sync."""

from __future__ import annotations

from typing import Any, Dict, Optional


def _norm_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def confidence_value(source: Dict[str, Any]) -> int:
    """Return STIX confidence as an integer; missing values count as 0."""
    value = _norm_int(source.get("confidence"))
    return value if value is not None else 0


def upstream_confidence_from_record(
    stored_record: Optional[Dict[str, Any]],
) -> Optional[int]:
    if not stored_record:
        return None
    return _norm_int(stored_record.get("upstream_confidence"))


def analyst_confidence_wins(
    opencti_entity: Dict[str, Any],
    *,
    api_item: Optional[Dict[str, Any]] = None,
    stored_record: Optional[Dict[str, Any]] = None,
) -> bool:
    """True when OpenCTI confidence exceeds Threat Library confidence."""
    opencti_conf = confidence_value(opencti_entity)
    if api_item is not None:
        api_conf = confidence_value(api_item)
    else:
        stored = upstream_confidence_from_record(stored_record)
        api_conf = stored if stored is not None else 0
    return opencti_conf > api_conf


def make_sync_record(api_item: Dict[str, Any]) -> Dict[str, Any]:
    """Build connector state after a successful push."""
    return {
        "upstream_confidence": confidence_value(api_item),
    }
