"""Connector state helpers.

OpenCTI connectors can persist a small JSON-compatible state blob via the
connector helper. This connector stores the last successfully processed API
page number so it can resume after a restart.

"""

from typing import Any, Mapping


def normalize_state(state: Any) -> dict[str, Any]:
    """Normalize arbitrary helper state into the expected dict structure.

    This is defensive: OpenCTI may return None, a non-dict, or unexpected types.
    """
    if not isinstance(state, dict):
        return {"last_page": 0}

    last_page = state.get("last_page", 0)
    try:
        last_page_int = max(0, int(last_page))
    except Exception:  # noqa: BLE001
        last_page_int = 0

    result: dict[str, Any] = {"last_page": last_page_int}
    if "last_run" in state and isinstance(state.get("last_run"), (int, float)):
        result["last_run"] = int(state["last_run"])
    return result


def load_state_from_helper(helper: Any) -> dict[str, Any]:
    """Load and normalize state from an OpenCTI connector helper."""
    raw = helper.get_state() if helper is not None else None
    return normalize_state(raw)


def save_state_to_helper(helper: Any, state: Mapping[str, Any]) -> None:
    """Normalize and persist state via the OpenCTI connector helper."""
    if helper is None:
        return
    helper.set_state(normalize_state(state))
