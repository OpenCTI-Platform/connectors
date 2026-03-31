"""
USTA connector utility functions.

Lightweight helpers shared across the connector modules.  Kept dependency-free
so they can be imported without the OpenCTI/STIX stack being present (useful in
unit tests that don't mock the full helper chain).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def iso_now() -> str:
    """Return the current UTC time as an ISO 8601 string (``YYYY-MM-DDTHH:MM:SSZ``)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_get(data: dict, *keys: str, default: Any = None) -> Any:
    """
    Safely traverse a nested dictionary without raising ``KeyError``.

    Stops early and returns *default* whenever an intermediate key is missing
    or the traversal hits a non-dict value.

    Args:
        data: The root dictionary to traverse.
        *keys: Sequence of keys forming the lookup path.
        default: Value to return when any key is absent.  Defaults to ``None``.

    Returns:
        The value at the end of the key path, or *default*.

    Example::

        safe_get(record, "hashes", "sha256")  # → record["hashes"]["sha256"]
        safe_get(record, "missing", "key")    # → None
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
