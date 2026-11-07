"""Parse timestamps returned by the Cyble engine document APIs."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def parse_engine_datetime(value: Any) -> datetime | None:
    """Parse an engine date, datetime, or Mongo ``$date`` wrapper."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        millis = value if value > 1_000_000_000_000 else value * 1000
        return datetime.fromtimestamp(millis / 1000, tz=timezone.utc)
    if isinstance(value, dict):
        inner = value.get("$date", value)
        if isinstance(inner, dict) and inner.get("$numberLong") is not None:
            return parse_engine_datetime(int(inner["$numberLong"]))
        return parse_engine_datetime(inner)

    text = str(value).strip()
    if len(text) == 10 and text[4] == "-" and text[7] == "-":
        return datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def iso_date(value: datetime) -> str:
    """Return YYYY-MM-DD in UTC."""
    return value.astimezone(timezone.utc).date().isoformat()


def next_page(page: int, page_size: int, total: int) -> int | None:
    """Return the next 1-based page, or None when the window is exhausted."""
    if page_size <= 0 or total <= 0:
        return None
    if page * page_size >= total:
        return None
    return page + 1
