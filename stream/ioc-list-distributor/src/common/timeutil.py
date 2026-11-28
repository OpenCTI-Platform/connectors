"""UTC timestamp helpers shared by the connector, the exporter and every storage backend.

Every timestamp is stored as UTC 'YYYY-MM-DDTHH:MM:SS.ffffffZ' (fixed width), so a text
comparison equals a time comparison in any database.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

_LONG_FRACTION = re.compile(r"(\.\d{6})\d+")


def iso(dt: datetime) -> str:
    """Fixed-width UTC text of a datetime."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def utcnow_iso() -> str:
    """The current time as fixed-width UTC text."""
    return iso(datetime.now(timezone.utc))


def to_iso(value: object) -> str | None:
    """Normalise a STIX timestamp; None if missing or unparseable."""
    if not value:
        return None
    text = str(value).strip()
    if text[-1:] in ("Z", "z"):
        text = text[:-1] + "+00:00"
    text = _LONG_FRACTION.sub(r"\1", text)
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    try:
        return iso(dt)
    except (OverflowError, ValueError):
        return None
