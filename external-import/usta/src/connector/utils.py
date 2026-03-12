"""
USTA Prodaft connector utility functions.
"""

from __future__ import annotations

from datetime import datetime, timezone


def iso_now() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_get(data: dict, *keys, default=None):
    """
    Safely traverse nested dictionaries.

    Example:
        safe_get(record, "hashes", "sha256") -> record["hashes"]["sha256"]
    """
    current = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        else:
            return default
        if current is None:
            return default
    return current
