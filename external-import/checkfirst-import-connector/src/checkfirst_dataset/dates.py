"""Date parsing helpers.

The API response includes a `Publication Date` string. We parse it using
`dateutil` and normalize the output to timezone-aware UTC datetimes.
"""

from datetime import datetime, timezone

from dateutil import parser as date_parser


class DateParseError(ValueError):
    """Raised when a publication date cannot be parsed."""

    pass


def parse_publication_date(value: str) -> datetime:
    """Parse the publication date string into a UTC datetime."""
    raw = (value or "").strip()
    if not raw:
        raise DateParseError("Publication Date is missing")

    try:
        parsed = date_parser.isoparse(raw)
    except Exception as exc:  # noqa: BLE001
        raise DateParseError(f"Unparseable Publication Date: {raw!r}") from exc

    if parsed.tzinfo is None:
        # If the API provides a naive datetime, treat it as UTC.
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
