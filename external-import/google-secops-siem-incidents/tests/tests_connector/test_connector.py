"""Tests for GoogleSecOpsConnector: instantiation, _collect_intelligence, process_message, run."""

import sys
from unittest.mock import AsyncMock, MagicMock, patch

from google_secops_siem_incidents import GoogleSecOpsConnector
from pycti import OpenCTIConnectorHelper
from test_helpers import make_stub_settings


# ===========================================================================
# BDD helpers
# ===========================================================================
def _given_connector_with_stubs(get_state_return=None):
    """Return a GoogleSecOpsConnector wired with a stubbed helper and empty-fetch API client."""
    settings = make_stub_settings()()

    helper = MagicMock(spec=OpenCTIConnectorHelper)
    helper.connect_name = "Test Google SecOps"
    helper.connect_id = "connector-id"
    helper.get_state.return_value = get_state_return
    helper.api = MagicMock()
    helper.api.work.initiate_work.return_value = "work-id-123"
    helper.stix2_create_bundle.return_value = '{"type": "bundle", "objects": []}'
    helper.connector_logger = MagicMock()

    connector = GoogleSecOpsConnector(config=settings, helper=helper)

    # Stub the client so asyncio.run(_async_process_message) is a no-op.
    async def _empty_fetch(*args, **kwargs):
        return
        yield  # makes this an async generator

    stub_client = MagicMock()
    stub_client.fetch_rule_alerts = _empty_fetch
    stub_client.close = AsyncMock()
    connector._client = stub_client

    return connector, helper, settings


def _when_collect_intelligence(connector):
    """Call _collect_intelligence and return its result."""
    return connector._collect_intelligence()


def _when_process_message(connector):
    """Call process_message."""
    connector.process_message()


def _when_run(connector):
    """Call run."""
    connector.run()


# ===========================================================================
# Connector instantiation — Scenarios 12-14
# ===========================================================================
def test_connector_instantiated_with_valid_config_and_helper():
    """GoogleSecOpsConnector can be instantiated with valid config and mocked helper — no exception."""
    connector, helper, settings = _given_connector_with_stubs()
    assert connector is not None


def test_connector_config_is_provided_settings():
    """After instantiation, connector.config is the provided settings instance."""
    connector, helper, settings = _given_connector_with_stubs()
    assert connector.config is settings


def test_connector_helper_is_provided_helper():
    """After instantiation, connector.helper is the provided helper instance."""
    connector, helper, settings = _given_connector_with_stubs()
    assert connector.helper is helper


# ===========================================================================
# _collect_intelligence — Scenario 15
# ===========================================================================
def test_collect_intelligence_runs_async_pipeline():
    """_collect_intelligence drives the async pipeline without returning data."""
    connector, _, _ = _given_connector_with_stubs()
    result = _when_collect_intelligence(connector)
    assert result is None


# ===========================================================================
# process_message — state management — Scenarios 16-20
# ===========================================================================
def test_process_message_logs_never_run_when_state_is_none():
    """On first run (get_state→None), the connector logs that it has never run."""
    connector, helper, _ = _given_connector_with_stubs(get_state_return=None)
    _when_process_message(connector)

    log_calls = helper.connector_logger.info.call_args_list
    logged_messages = " ".join(str(c) for c in log_calls)
    assert "never run" in logged_messages.lower()


def test_process_message_logs_never_run_when_state_is_empty_dict():
    """On first run (get_state→{}), the connector logs that it has never run."""
    connector, helper, _ = _given_connector_with_stubs(get_state_return={})
    _when_process_message(connector)

    log_calls = helper.connector_logger.info.call_args_list
    logged_messages = " ".join(str(c) for c in log_calls)
    assert "never run" in logged_messages.lower()


def test_process_message_logs_last_run_when_state_has_last_run():
    """On subsequent run, the connector logs the last run datetime."""
    past_state = {"last_run": "2025-01-01 12:00:00"}
    connector, helper, _ = _given_connector_with_stubs(get_state_return=past_state)
    _when_process_message(connector)

    log_calls = helper.connector_logger.info.call_args_list
    logged_messages = " ".join(str(c) for c in log_calls)
    assert "2025-01-01 12:00:00" in logged_messages


def test_process_message_updates_state_after_success():
    """After a successful run, set_state is called with a dict containing last_run."""
    connector, helper, _ = _given_connector_with_stubs(get_state_return=None)
    _when_process_message(connector)

    helper.set_state.assert_called_once()
    state_arg = helper.set_state.call_args[0][0]
    assert "last_run" in state_arg
    assert isinstance(state_arg["last_run"], str)


def test_process_message_updates_state_even_when_collect_is_no_op():
    """State is updated (last_run written) even when _collect_intelligence is a no-op."""
    connector, helper, _ = _given_connector_with_stubs(get_state_return=None)
    with patch.object(connector, "_collect_intelligence", return_value=None):
        _when_process_message(connector)

    helper.set_state.assert_called_once()
    state_arg = helper.set_state.call_args[0][0]
    assert "last_run" in state_arg


# ===========================================================================
# process_message — error handling — Scenario 24
# ===========================================================================
def test_process_message_calls_sys_exit_on_keyboard_interrupt():
    """When _collect_intelligence raises KeyboardInterrupt, sys.exit(0) is called."""
    connector, helper, _ = _given_connector_with_stubs(get_state_return=None)

    with (
        patch.object(connector, "_collect_intelligence", side_effect=KeyboardInterrupt),
        patch.object(sys, "exit") as mock_exit,
    ):
        _when_process_message(connector)

    mock_exit.assert_called_once_with(0)


# ===========================================================================
# Scheduler — Scenario 26
# ===========================================================================
def test_run_calls_schedule_process_with_correct_args():
    """run calls helper.schedule_process with process_message callback and duration 3600.0."""
    connector, helper, _ = _given_connector_with_stubs()
    _when_run(connector)

    helper.schedule_process.assert_called_once()
    kwargs = helper.schedule_process.call_args
    # Check keyword arguments
    assert kwargs.kwargs.get("message_callback") == connector.process_message or (
        kwargs[1].get("message_callback") == connector.process_message
        if len(kwargs) > 1
        else False
    )
    duration = kwargs.kwargs.get("duration_period") or kwargs[1].get("duration_period")
    assert duration == 3600.0
