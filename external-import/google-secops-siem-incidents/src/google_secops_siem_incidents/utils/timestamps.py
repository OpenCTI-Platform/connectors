"""Shared timestamp parsing utilities."""

from datetime import datetime


def parse_ts(ts: str) -> datetime:
    """Parse an ISO-8601 timestamp (with 'Z' or offset) to a timezone-aware datetime.

    Args:
        ts: ISO-8601 timestamp string.

    Returns:
        Timezone-aware datetime instance.
    """
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))
