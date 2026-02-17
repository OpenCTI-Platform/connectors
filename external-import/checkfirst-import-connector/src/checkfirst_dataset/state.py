from __future__ import annotations

"""Connector state helpers.

OpenCTI connectors can persist a small JSON-compatible state blob via the
connector helper. This connector stores a per-file cursor (row index) under a
`files` mapping.

State shape (normalized):
{
    "files": {
        "relative/path.csv": {"cursor": 123},
        ...
    }
}
"""

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class FileState:
    """State stored for a single dataset file."""

    cursor: int = 0


def normalize_state(state: Any) -> dict[str, Any]:
    """Normalize arbitrary helper state into the expected dict structure.

    This is defensive: OpenCTI may return None, a non-dict, or unexpected types.
    """
    if not isinstance(state, dict):
        return {"files": {}}

    files = state.get("files")
    if not isinstance(files, dict):
        files = {}

    normalized_files: dict[str, Any] = {}
    for key, value in files.items():
        if not isinstance(key, str):
            continue
        if isinstance(value, dict):
            cursor = value.get("cursor", 0)
        else:
            cursor = 0
        try:
            cursor_int = int(cursor)
        except Exception:  # noqa: BLE001
            cursor_int = 0
        normalized_files[key] = {"cursor": max(0, cursor_int)}

    return {"files": normalized_files}


def get_file_cursor(state: Mapping[str, Any], file_key: str) -> int:
    """Read a file cursor from normalized state, defaulting to 0."""
    files = state.get("files", {})
    if not isinstance(files, dict):
        return 0
    entry = files.get(file_key, {})
    if not isinstance(entry, dict):
        return 0
    cursor = entry.get("cursor", 0)
    try:
        return max(0, int(cursor))
    except Exception:  # noqa: BLE001
        return 0


def set_file_cursor(
    state: Mapping[str, Any], file_key: str, cursor: int
) -> dict[str, Any]:
    """Return a new normalized state with an updated cursor for `file_key`."""
    normalized = normalize_state(state)
    normalized["files"][file_key] = {"cursor": max(0, int(cursor))}
    return normalized


def load_state_from_helper(helper: Any) -> dict[str, Any]:
    """Load and normalize state from an OpenCTI connector helper."""
    # OpenCTI helper returns a dict-like object; be defensive.
    raw = helper.get_state() if helper is not None else None
    return normalize_state(raw)


def save_state_to_helper(helper: Any, state: Mapping[str, Any]) -> None:
    """Normalize and persist state via the OpenCTI connector helper."""
    if helper is None:
        return
    helper.set_state(normalize_state(state))
