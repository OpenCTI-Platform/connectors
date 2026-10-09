"""Module to test the WorkManager class."""

from typing import Any
from unittest.mock import MagicMock

import pytest
from connector.src.octi.work_manager import WorkManager

# =====================
# Fixtures
# =====================


@pytest.fixture
def fake_helper() -> Any:
    """Fixture for a fake OpenCTI connector helper."""
    helper = MagicMock()
    helper.connect_id = "connector-id"
    return helper


@pytest.fixture
def work_manager(fake_helper: Any) -> WorkManager:
    """Fixture for a WorkManager instance backed by a fake helper."""
    return WorkManager(config=MagicMock(), helper=fake_helper)


# =====================
# Test Cases
# =====================


# Scenario: Get the current state of the connector
def test_get_state_returns_helper_state(
    work_manager: WorkManager, fake_helper: Any
) -> None:
    """Test that get_state pings the helper and returns its state."""
    fake_helper.get_state.return_value = {"key": "value"}
    result = work_manager.get_state()
    fake_helper.force_ping.assert_called_once()
    assert result == {"key": "value"}  # noqa: S101


# Scenario: Get the current state when the helper returns no state
def test_get_state_defaults_to_empty_dict(
    work_manager: WorkManager, fake_helper: Any
) -> None:
    """Test that get_state returns an empty dict when the helper has no state."""
    fake_helper.get_state.return_value = None
    result = work_manager.get_state()
    assert result == {}  # noqa: S101


# Scenario: Track the current work ID
def test_set_and_get_current_work_id(work_manager: WorkManager) -> None:
    """Test that set_current_work_id updates the value returned by get_current_work_id."""
    assert work_manager.get_current_work_id() is None  # noqa: S101
    work_manager.set_current_work_id("work-123")
    assert work_manager.get_current_work_id() == "work-123"  # noqa: S101


# Scenario: Update the state with a valid ISO date string
def test_update_state_with_valid_iso_date(
    work_manager: WorkManager, fake_helper: Any
) -> None:
    """Test that update_state stores a provided valid ISO date string as-is."""
    fake_helper.get_state.return_value = {}
    work_manager.update_state("next_cursor_start_date", "2024-07-11T20:05:01+00:00")
    fake_helper.set_state.assert_called_once()
    stored_state = fake_helper.set_state.call_args.kwargs["state"]
    assert (
        stored_state["next_cursor_start_date"] == "2024-07-11T20:05:01+00:00"
    )  # noqa: S101


# Scenario: Update the state with a date string that is not ISO-parsable at all
def test_update_state_with_unparsable_date_string_raises(
    work_manager: WorkManager, fake_helper: Any
) -> None:
    """Test that update_state propagates ValueError for a date string fromisoformat rejects.

    The fallback branch re-parses the same string with the same
    datetime.fromisoformat(date_str.replace("Z", "+00:00")) call used by
    _is_valid_iso_format, so any string that fails validation also fails the
    fallback parse and raises uncaught - this documents that current behavior.
    """
    fake_helper.get_state.return_value = {}
    with pytest.raises(ValueError):
        work_manager.update_state("next_cursor_start_date", "11/07/2024")


# Scenario: Check validity of a well-formed ISO date string
def test_is_valid_iso_format_true_for_iso_date() -> None:
    """Test that _is_valid_iso_format accepts a valid ISO date string."""
    assert WorkManager._is_valid_iso_format("2024-07-11T20:05:01+00:00")  # noqa: S101


# Scenario: Check validity of a malformed date string
def test_is_valid_iso_format_false_for_invalid_date() -> None:
    """Test that _is_valid_iso_format rejects a non-ISO date string."""
    assert not WorkManager._is_valid_iso_format("11/07/2024")  # noqa: S101


# Scenario: Update the state without providing a date string
def test_update_state_without_date_string_uses_now(
    work_manager: WorkManager, fake_helper: Any
) -> None:
    """Test that update_state defaults to the current time when no date string is given."""
    fake_helper.get_state.return_value = {}
    work_manager.update_state("next_cursor_start_date")
    stored_state = fake_helper.set_state.call_args.kwargs["state"]
    assert "next_cursor_start_date" in stored_state  # noqa: S101


# Scenario: Update the state is skipped when an error occurred
def test_update_state_skipped_on_error_flag(
    work_manager: WorkManager, fake_helper: Any
) -> None:
    """Test that update_state does nothing when error_flag is True."""
    work_manager.update_state(
        "next_cursor_start_date", "2024-07-11T20:05:01+00:00", error_flag=True
    )
    fake_helper.set_state.assert_not_called()


# Scenario: Initiate a new work item without a counter
def test_initiate_work_without_counter(
    work_manager: WorkManager, fake_helper: Any
) -> None:
    """Test that initiate_work creates and tracks a new work item."""
    fake_helper.api.work.initiate_work.return_value = "work-1"
    result = work_manager.initiate_work("Import reports")
    fake_helper.api.work.initiate_work.assert_called_once_with(
        "connector-id", "Import reports"
    )
    assert result == "work-1"  # noqa: S101
    assert work_manager.get_current_work_id() == "work-1"  # noqa: S101


# Scenario: Initiate a new work item with a counter
def test_initiate_work_with_counter(
    work_manager: WorkManager, fake_helper: Any
) -> None:
    """Test that initiate_work appends the counter to the work name."""
    fake_helper.api.work.initiate_work.return_value = "work-2"
    work_manager.initiate_work("Import reports", work_counter=3)
    fake_helper.api.work.initiate_work.assert_called_once_with(
        "connector-id", "Import reports #(3)"
    )


# Scenario: Mark a work item as processed successfully
def test_work_to_process_success_clears_current_work_id(
    work_manager: WorkManager, fake_helper: Any
) -> None:
    """Test that work_to_process reports success and clears the current work ID if matching."""
    work_manager.set_current_work_id("work-1")
    work_manager.work_to_process("work-1")
    fake_helper.api.work.to_processed.assert_called_once_with(
        work_id="work-1", message="Connector's work finished gracefully", in_error=False
    )
    assert work_manager.get_current_work_id() is None  # noqa: S101


# Scenario: Mark a work item as processed with an error message
def test_work_to_process_with_error(
    work_manager: WorkManager, fake_helper: Any
) -> None:
    """Test that work_to_process reports the specific error message when in error."""
    work_manager.work_to_process("work-1", error_flag=True, error_message="boom")
    fake_helper.api.work.to_processed.assert_called_once_with(
        work_id="work-1", message="Error: boom", in_error=True
    )


# Scenario: Process all remaining incomplete works
def test_process_all_remaining_works_processes_incomplete(
    work_manager: WorkManager, fake_helper: Any
) -> None:
    """Test that process_all_remaining_works only processes incomplete works."""
    fake_helper.api.work.get_connector_works.return_value = [
        {"id": "work-1", "status": "complete"},
        {"id": "work-2", "status": "in-progress"},
    ]
    work_manager.process_all_remaining_works()
    fake_helper.api.work.to_processed.assert_called_once_with(
        work_id="work-2", message="Connector's work finished gracefully", in_error=False
    )
    assert work_manager.get_current_work_id() is None  # noqa: S101


# Scenario: Send a STIX bundle to OpenCTI
def test_send_bundle(work_manager: WorkManager, fake_helper: Any) -> None:
    """Test that send_bundle creates and sends a STIX bundle, logging the result."""
    fake_helper.stix2_create_bundle.return_value = "bundle-json"
    fake_helper.send_stix2_bundle.return_value = ["a", "b"]
    work_manager.send_bundle("work-1", ["item"])
    fake_helper.stix2_create_bundle.assert_called_once_with(["item"])
    fake_helper.send_stix2_bundle.assert_called_once_with(
        bundle="bundle-json", work_id="work-1", cleanup_inconsistent_bundle=True
    )
