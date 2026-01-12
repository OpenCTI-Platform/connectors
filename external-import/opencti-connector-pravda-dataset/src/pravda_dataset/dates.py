from __future__ import annotations

from datetime import datetime, timezone

from dateutil import parser as date_parser


class DateParseError(ValueError):
    pass


def parse_publication_date(value: str) -> datetime:
    raw = (value or "").strip()
    if not raw:
        raise DateParseError("Publication Date is missing")

    try:
        parsed = date_parser.isoparse(raw)
    except Exception as exc:  # noqa: BLE001
        raise DateParseError(f"Unparseable Publication Date: {raw!r}") from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
