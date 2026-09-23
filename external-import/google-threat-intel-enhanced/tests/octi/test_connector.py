"""Module to test the Connector class (connector/src/octi/connector.py)."""

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from connector.src.custom.exceptions.connector_errors.gti_work_processing_error import (
    GTIWorkProcessingError,
)
from connector.src.octi.connector import Connector

# =====================
# Fixtures
# =====================


@pytest.fixture
def fake_helper() -> Any:
    """Fixture for a fake OpenCTI connector helper."""
    helper = MagicMock()
    helper.connect_name = "GTI Enhanced"
    return helper


@pytest.fixture
def fake_gti_config() -> Any:
    """Fixture for a fake GTI configuration with reports import enabled."""
    gti_config = MagicMock()
    gti_config.import_reports = True
    return gti_config


@pytest.fixture
def fake_global_config(fake_gti_config: Any) -> Any:
    """Fixture for a fake GlobalConfig returning the fake GTI configuration."""
    global_config = MagicMock()
    global_config.get_config_class.return_value = fake_gti_config
    global_config.connector_config.tlp_level = "amber+strict"
    return global_config


@pytest.fixture
def connector(fake_global_config: Any, fake_helper: Any) -> Connector:
    """Fixture for a Connector instance wired with fakes."""
    return Connector(fake_global_config, fake_helper)


# =====================
# Test Cases: run
# =====================


# Scenario: Running the connector delegates scheduling to the helper
def test_run_delegates_to_helper_scheduler(
    connector: Connector, fake_helper: Any, fake_global_config: Any
) -> None:
    """Test that run() schedules _process_callback via the helper's scheduler."""
    fake_global_config.connector_config.duration_period = "PT2H"
    connector.run()
    fake_helper.schedule_iso.assert_called_once_with(
        message_callback=connector._process_callback, duration_period="PT2H"
    )


# =====================
# Test Cases: _process_callback
# =====================


# Scenario: The callback processes GTI reports successfully
def test_process_callback_success(connector: Connector) -> None:
    """Test that _process_callback runs report processing and marks works processed."""
    with patch.object(
        Connector, "_process_gti_reports", new=AsyncMock(return_value=None)
    ):
        with patch.object(
            connector.work_manager, "process_all_remaining_works"
        ) as m_cleanup:
            connector._process_callback()
    m_cleanup.assert_called_once_with(error_flag=False, error_message=None)


# Scenario: The callback skips processing when reports import is disabled
def test_process_callback_reports_disabled(
    connector: Connector, fake_gti_config: Any
) -> None:
    """Test that _process_callback does not process reports when import_reports is False."""
    fake_gti_config.import_reports = False
    with patch.object(Connector, "_process_gti_reports") as m_process:
        connector._process_callback()
    m_process.assert_not_called()


# Scenario: The callback reports an error message returned by report processing
def test_process_callback_reports_processing_error_message(
    connector: Connector,
) -> None:
    """Test that _process_callback marks an error flag when report processing returns a message."""
    with patch.object(
        Connector, "_process_gti_reports", new=AsyncMock(return_value="failed hard")
    ):
        with patch.object(
            connector.work_manager, "process_all_remaining_works"
        ) as m_cleanup:
            connector._process_callback()
    m_cleanup.assert_called_once_with(error_flag=True, error_message="failed hard")


# Scenario: The callback fails to load the GTI configuration
def test_process_callback_gti_config_load_failure(
    connector: Connector, fake_global_config: Any
) -> None:
    """Test that _process_callback wraps configuration loading failures as GTIConfigurationError."""
    fake_global_config.get_config_class.side_effect = ValueError("bad config")
    with patch.object(
        connector.work_manager, "process_all_remaining_works"
    ) as m_cleanup:
        connector._process_callback()
    assert m_cleanup.call_args.kwargs["error_flag"] is True  # noqa: S101


# Scenario: The callback is interrupted by the user/system and re-raises
def test_process_callback_keyboard_interrupt_reraises(connector: Connector) -> None:
    """Test that _process_callback logs and re-raises KeyboardInterrupt."""
    with patch.object(
        Connector, "_process_gti_reports", side_effect=KeyboardInterrupt()
    ):
        with pytest.raises(KeyboardInterrupt):
            connector._process_callback()


# Scenario: The callback handles a cancelled operation
def test_process_callback_cancelled_error(connector: Connector) -> None:
    """Test that _process_callback logs and swallows asyncio.CancelledError."""
    with patch.object(
        Connector,
        "_process_gti_reports",
        new=AsyncMock(side_effect=asyncio.CancelledError()),
    ):
        connector._process_callback()


# Scenario: The callback handles a GTIWorkProcessingError raised during processing
def test_process_callback_work_processing_error(connector: Connector) -> None:
    """Test that _process_callback logs a warning and continues on GTIWorkProcessingError."""
    work_err = GTIWorkProcessingError("work failed")
    with patch.object(
        Connector, "_process_gti_reports", new=AsyncMock(side_effect=work_err)
    ):
        connector._process_callback()


# Scenario: The callback handles an unexpected error during processing
def test_process_callback_unexpected_error(connector: Connector) -> None:
    """Test that _process_callback logs an error and continues on unexpected exceptions."""
    with patch.object(
        Connector,
        "_process_gti_reports",
        new=AsyncMock(side_effect=RuntimeError("boom")),
    ):
        connector._process_callback()


# Scenario: Cleanup itself fails after processing
def test_process_callback_cleanup_failure_is_logged(connector: Connector) -> None:
    """Test that _process_callback logs cleanup errors without raising."""
    with patch.object(
        Connector, "_process_gti_reports", new=AsyncMock(return_value=None)
    ):
        with patch.object(
            connector.work_manager,
            "process_all_remaining_works",
            side_effect=RuntimeError("cleanup failed"),
        ):
            connector._process_callback()


# =====================
# Test Cases: _process_gti_reports
# =====================


# Scenario: GTI report processing runs the orchestrator end-to-end
@pytest.mark.asyncio
async def test_process_gti_reports_runs_orchestrator(
    connector: Connector, fake_helper: Any, fake_gti_config: Any
) -> None:
    """Test that _process_gti_reports builds and runs an Orchestrator with the current state."""
    fake_helper.get_state.return_value = {"next_cursor_start_date": "2024-01-01"}
    fake_orchestrator = MagicMock()
    fake_orchestrator.run = AsyncMock(return_value=None)
    with patch(
        "connector.src.custom.orchestrators.orchestrator.Orchestrator",
        return_value=fake_orchestrator,
    ):
        await connector._process_gti_reports(fake_gti_config)
    fake_orchestrator.run.assert_called_once_with(
        {"next_cursor_start_date": "2024-01-01"}
    )


# Scenario: GTI report processing fails and the error is logged, not raised
@pytest.mark.asyncio
async def test_process_gti_reports_handles_failure(
    connector: Connector, fake_helper: Any, fake_gti_config: Any
) -> None:
    """Test that _process_gti_reports logs and swallows errors raised while orchestrating."""
    fake_helper.get_state.return_value = {}
    with patch(
        "connector.src.custom.orchestrators.orchestrator.Orchestrator",
        side_effect=RuntimeError("orchestrator init failed"),
    ):
        await connector._process_gti_reports(fake_gti_config)
