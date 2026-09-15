"""Unit tests for Lab539AiTMConnector orchestration logic."""

from datetime import datetime, timezone
from unittest.mock import Mock

import pytest
from lab539_aitm_connector.connector import Lab539AiTMConnector


@pytest.fixture
def connector(mock_config, mock_helper):
    """A connector instance with the API client and converter mocked out."""
    instance = Lab539AiTMConnector(config=mock_config, helper=mock_helper)
    instance.client = Mock()
    instance.converter = Mock()
    return instance


def test_get_last_run_returns_none_without_state(connector, mock_helper):
    mock_helper.get_state.return_value = None
    assert connector._get_last_run() is None


def test_get_last_run_accepts_int(connector, mock_helper):
    mock_helper.get_state.return_value = {"last_run": 1778919394}
    assert connector._get_last_run() == 1778919394


def test_get_last_run_parses_isoformat(connector, mock_helper):
    mock_helper.get_state.return_value = {"last_run": "2026-01-01T00:00:00+00:00"}
    expected = int(datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp())
    assert connector._get_last_run() == expected


def test_set_last_run_persists_isoformat(connector, mock_helper):
    mock_helper.get_state.return_value = {}
    now = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    connector._set_last_run(now)
    state = mock_helper.set_state.call_args.args[0]
    assert state["last_run"] == "2026-01-02T03:04:05+00:00"


@pytest.mark.parametrize(
    "current,stored,expected",
    [
        (None, "A", True),
        ("A", None, True),
        ("A", "A", False),
        ("B", "A", True),
    ],
)
def test_is_new_data_available(connector, mock_helper, current, stored, expected):
    mock_helper.get_state.return_value = {"last_event_id": stored} if stored else {}
    assert connector._is_new_data_available(current) is expected


def test_update_last_event_id_sets_state(connector, mock_helper):
    mock_helper.get_state.return_value = {}
    connector._update_last_event_id("EVT-1")
    assert mock_helper.set_state.call_args.args[0]["last_event_id"] == "EVT-1"


def test_update_last_event_id_noop_when_none(connector, mock_helper):
    connector._update_last_event_id(None)
    mock_helper.set_state.assert_not_called()


def test_process_message_skips_when_no_new_data(connector, mock_helper):
    connector.client.get_last_event.return_value = "SAME"
    mock_helper.get_state.return_value = {"last_event_id": "SAME"}

    connector.process_message()

    connector.client.get_records.assert_not_called()
    connector.converter.records_to_bundle.assert_not_called()


def test_process_message_first_run_uses_lookback(connector, mock_helper):
    connector.client.get_last_event.return_value = "EVT-1"
    mock_helper.get_state.return_value = {}
    connector.client.get_records.return_value = [{"eventid": "e1"}]

    connector.process_message()

    # First run pulls with an "after" lookback timestamp, not an empty call.
    assert "after" in connector.client.get_records.call_args.kwargs
    connector.converter.records_to_bundle.assert_called_once()
    mock_helper.send_stix2_bundle.assert_called_once()


def test_process_message_incremental_uses_last_run(connector, mock_helper):
    connector.client.get_last_event.return_value = "EVT-2"
    mock_helper.get_state.return_value = {
        "last_run": 1778919394,
        "last_event_id": "EVT-1",
    }
    connector.client.get_records.return_value = [{"eventid": "e1"}]

    connector.process_message()

    assert connector.client.get_records.call_args.kwargs.get("after") == 1778919394
    mock_helper.send_stix2_bundle.assert_called_once()


def test_process_message_no_records_sets_last_run(connector, mock_helper):
    connector.client.get_last_event.return_value = "EVT-3"
    mock_helper.get_state.return_value = {}
    connector.client.get_records.return_value = []

    connector.process_message()

    connector.converter.records_to_bundle.assert_not_called()
    mock_helper.set_state.assert_called()


def test_process_message_handles_fetch_error(connector, mock_helper):
    connector.client.get_last_event.return_value = "EVT-4"
    mock_helper.get_state.return_value = {}
    connector.client.get_records.side_effect = RuntimeError("api down")

    connector.process_message()

    connector.converter.records_to_bundle.assert_not_called()
    mock_helper.connector_logger.error.assert_called()


def test_process_message_handles_convert_error(connector, mock_helper):
    connector.client.get_last_event.return_value = "EVT-5"
    mock_helper.get_state.return_value = {}
    connector.client.get_records.return_value = [{"eventid": "e1"}]
    connector.converter.records_to_bundle.side_effect = ValueError("bad record")

    connector.process_message()

    mock_helper.send_stix2_bundle.assert_not_called()
    mock_helper.connector_logger.error.assert_called()


def test_run_schedules_iso(connector, mock_helper):
    connector.run()
    mock_helper.schedule_iso.assert_called_once()


def test_handle_interrupt_exits():
    with pytest.raises(SystemExit):
        Lab539AiTMConnector.handle_interrupt()
