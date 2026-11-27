"""Markdown blocks for GTI fields with no matching STIX property, appended to descriptions."""

from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any

EMPTY_VALUES: tuple[Any, ...] = (None, "", [])


def format_date(timestamp: int | None) -> str | None:
    """Format a UTC timestamp as YYYY-MM-DD."""
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d")


def bullet_section(title: str, lines: Iterable[str]) -> str | None:
    """Return a titled bullet list, or None when there is no line."""
    bullets = [f"- {line}" for line in lines]
    if not bullets:
        return None
    return f"**{title}**\n\n" + "\n".join(bullets)


def details_section(title: str, details: Mapping[str, Any]) -> str | None:
    """Return a titled 'label: value' bullet list, skipping empty values.

    List values are comma-joined.
    """
    return bullet_section(
        title,
        (
            f"{label}: {', '.join(map(str, value)) if isinstance(value, list) else value}"
            for label, value in details.items()
            if value not in EMPTY_VALUES
        ),
    )


def join_sections(*sections: str | None) -> str | None:
    """Join the non-empty sections with blank lines, or None when all are empty."""
    parts = [section.strip() for section in sections if section and section.strip()]
    return "\n\n".join(parts) if parts else None
