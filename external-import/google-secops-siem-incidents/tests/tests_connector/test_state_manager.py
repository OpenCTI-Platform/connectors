"""Unit tests for GoogleSecOpsSIEMState (S-01 through S-04) using _given_/_when_/_then_ BDD helpers."""

from unittest.mock import MagicMock

from google_secops_siem_incidents.state_manager import GoogleSecOpsSIEMState
from pycti import OpenCTIConnectorHelper

# ===========================================================================
# Helpers
# ===========================================================================


def _make_mock_helper(initial_state: dict | None = None) -> MagicMock:
    """Build a mock OpenCTIConnectorHelper with stateful get/set_state that passes the SDK isinstance guard."""
    helper = MagicMock(spec=OpenCTIConnectorHelper)
    helper.connect_name = "Google SecOps"
    helper.connect_id = "test-connector-id"

    _state: dict = dict(initial_state or {})
    helper.get_state.side_effect = lambda: dict(_state) if _state else {}

    def _set_state(s: dict) -> None:
        _state.clear()
        _state.update(s)

    helper.set_state.side_effect = _set_state
    helper.force_ping = MagicMock()
    return helper


# ===========================================================================
# S-01: Fields default to None on fresh instantiation
# ===========================================================================


def test_s01_fresh_state_fields_default_to_none() -> None:
    """S-01: A freshly created state has all fields set to None."""
    # _given_ a fresh state manager with no prior OpenCTI state
    helper = _make_mock_helper()
    state = _given_fresh_state(helper)

    # _then_ all fields default to None
    _then_field_is_none(state, "last_alert_timestamp")
    _then_field_is_none(state, "pagination_checkpoint")
    _then_field_is_none(state, "last_run")


def _given_fresh_state(helper: MagicMock) -> GoogleSecOpsSIEMState:
    """Instantiate state with no prior OpenCTI data."""
    state = GoogleSecOpsSIEMState()
    state.inject_dependencies(helper)
    return state


def _then_field_is_none(state: GoogleSecOpsSIEMState, field: str) -> None:
    value = getattr(state, field)
    assert value is None, f"Expected {field} to be None, got {value!r}"  # noqa: S101


# ===========================================================================
# S-02: load() populates fields from OpenCTI state
# ===========================================================================


def test_s02_load_populates_fields_from_opencti() -> None:
    """S-02: After load(), fields match what OpenCTI returned."""
    # _given_ a saved OpenCTI state with last_alert_timestamp and last_run
    opencti_state = {
        "last_alert_timestamp": "2025-01-01T10:00:00+00:00",
        "last_run": "2025-01-01 10:00:00",
    }
    helper = _make_mock_helper(initial_state=opencti_state)
    state = _given_fresh_state(helper)

    # _when_ load() is called
    _when_load_is_called(state)

    # _then_ fields match the loaded OpenCTI state
    _then_last_alert_timestamp_equals(state, "2025-01-01T10:00:00+00:00")
    _then_last_run_is_populated(state)


def _when_load_is_called(state: GoogleSecOpsSIEMState) -> None:
    state.load()


def _then_last_alert_timestamp_equals(
    state: GoogleSecOpsSIEMState, expected_iso: str
) -> None:
    actual = state.last_alert_timestamp
    assert (
        actual is not None
    ), "last_alert_timestamp should not be None after load()"  # noqa: S101
    assert (
        actual.isoformat() == expected_iso
    ), (  # noqa: S101
        f"Expected last_alert_timestamp '{expected_iso}', got {actual.isoformat()!r}"
    )


def _then_last_run_is_populated(state: GoogleSecOpsSIEMState) -> None:
    assert (
        state.last_run is not None
    ), "last_run should be populated after load()"  # noqa: S101


# ===========================================================================
# S-03: save() calls helper.set_state + helper.force_ping
# ===========================================================================


def test_s03_save_calls_set_state_and_force_ping() -> None:
    """S-03: save() persists declared fields and pings the platform."""
    # _given_ a state with last_alert_timestamp set
    helper = _make_mock_helper()
    state = _given_state_with_alert_timestamp(helper, "2025-01-01T11:00:00+00:00")

    # _when_ save() is called
    _when_save_is_called(state)

    # _then_ set_state and force_ping were each called once
    _then_set_state_called_once_with_last_alert_timestamp(helper)
    _then_force_ping_called_once(helper)


def _given_state_with_alert_timestamp(
    helper: MagicMock, timestamp: str
) -> GoogleSecOpsSIEMState:
    """Instantiate state, load, then set last_alert_timestamp."""
    state = GoogleSecOpsSIEMState()
    state.inject_dependencies(helper)
    state.load()
    state.last_alert_timestamp = timestamp
    return state


def _when_save_is_called(state: GoogleSecOpsSIEMState) -> None:
    state.save()


def _then_set_state_called_once_with_last_alert_timestamp(helper: MagicMock) -> None:
    helper.set_state.assert_called_once()  # noqa: S101
    saved_dict = helper.set_state.call_args[0][0]
    assert (
        "last_alert_timestamp" in saved_dict
    ), f"Expected 'last_alert_timestamp' in saved state, got keys: {list(saved_dict.keys())}"  # noqa: S101


def _then_force_ping_called_once(helper: MagicMock) -> None:
    helper.force_ping.assert_called_once()  # noqa: S101


# ===========================================================================
# S-04: save() with pagination_checkpoint=None excludes that key
# ===========================================================================


def test_s04_save_excludes_none_pagination_checkpoint() -> None:
    """S-04: After clearing pagination_checkpoint, save() does not persist it."""
    # _given_ a state loaded from OpenCTI with a pagination_checkpoint, then checkpoint cleared
    initial_state = {
        "last_alert_timestamp": "2025-01-01T10:00:00+00:00",
        "pagination_checkpoint": {
            "window_start": "2025-01-01T09:00:00+00:00",
            "window_end": "2025-01-01T10:00:00+00:00",
            "run_max_ts": "2025-01-01T10:00:00+00:00",
        },
    }
    helper = _make_mock_helper(initial_state=initial_state)
    state = _given_fresh_state(helper)
    state.load()

    # _when_ — clear the pagination checkpoint and save
    state.pagination_checkpoint = None
    _when_save_is_called(state)

    # _then_ — pagination_checkpoint absent or explicitly None in saved dict
    _then_pagination_checkpoint_absent_or_none(helper)


def _then_pagination_checkpoint_absent_or_none(helper: MagicMock) -> None:
    saved_dict = helper.set_state.call_args[0][0]
    if "pagination_checkpoint" in saved_dict:
        assert (
            saved_dict["pagination_checkpoint"] is None
        ), f"pagination_checkpoint should be None if present, got {saved_dict['pagination_checkpoint']!r}"  # noqa: S101
