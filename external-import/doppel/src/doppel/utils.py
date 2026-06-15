from datetime import datetime, timezone


def parse_iso_datetime(timestamp_str: object | None) -> datetime | None:
    """
    Parse an ISO-8601 string into a timezone-aware datetime.

    A trailing ``Z`` (UTC designator, common in API payloads) is normalized to
    ``+00:00`` so it parses on every supported Python version. Inputs without an
    offset (which ``datetime.fromisoformat`` parses as naive) are assumed to be
    UTC, so callers always get a timezone-aware value. Returns ``None`` when the
    input is missing or cannot be parsed, so callers can fall back to a sensible
    default instead of feeding ``None`` into STIX objects.

    :return: datetime or None
    """
    if not timestamp_str or not isinstance(timestamp_str, str):
        return None
    normalized = timestamp_str
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed
