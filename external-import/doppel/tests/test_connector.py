from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from doppel.connector import DoppelConnector

RUN_START = datetime(2026, 8, 3, 12, 0, 0, tzinfo=timezone.utc)
WINDOW_END = "2026-08-03 12:00:00"


class FrozenDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return RUN_START


@pytest.fixture
def doppel_connector(monkeypatch):
    helper = MagicMock()
    helper.connect_id = "connector-id"
    helper.connect_name = "Doppel"
    helper.get_state.return_value = {"last_run": "2026-08-03 10:00:00"}
    helper.api.work.initiate_work.return_value = "work-1"
    helper.send_stix2_bundle.return_value = ["stix-object"]

    config = SimpleNamespace(
        doppel=SimpleNamespace(
            tlp_level="clear",
            enable_incidents=False,
            enable_grouping_case=False,
            enable_rft_case=False,
            page_size=100,
            historical_polling_days=30,
        ),
        connector=SimpleNamespace(),
    )
    monkeypatch.setattr("doppel.connector.datetime", FrozenDateTime)
    with (
        patch("doppel.connector.ConnectorClient"),
        patch("doppel.connector.ConverterToStix"),
    ):
        connector = DoppelConnector(config, helper)
    connector.converter.convert_alerts_to_stix.return_value = "bundle"
    return connector, helper


def _record_last_runs(helper):
    stored = []

    def record(state):
        stored.append(state["last_run"])

    helper.set_state.side_effect = record
    return stored


def test_process_message_failure_on_second_page_keeps_first_checkpoint(
    doppel_connector,
):
    connector, helper = doppel_connector
    connector.config.doppel.page_size = 2
    stored = _record_last_runs(helper)
    first_page = [
        {"id": "alert-1", "last_activity_timestamp": "2026-08-03T10:01:00Z"},
        {
            "id": "alert-2",
            "last_activity_timestamp": "2026-08-03T10:05:09.500000Z",
        },
    ]

    def get_alerts(**_kwargs):
        if connector.client.get_alerts.call_count == 1:
            return first_page, 2
        raise RuntimeError("page 2 failed")

    connector.client.get_alerts.side_effect = get_alerts

    connector.process_message()

    assert stored == ["2026-08-03 10:05:09"]
    helper.send_stix2_bundle.assert_called_once()
    connector.converter.convert_alerts_to_stix.assert_called_once_with(first_page)
    helper.api.work.initiate_work.assert_called_once()
    helper.api.work.to_processed.assert_called_once()
    assert helper.api.work.to_processed.call_args.args[0] == "work-1"
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is True
    assert connector.client.get_alerts.call_args_list[1].kwargs["page"] == 0
    assert (
        connector.client.get_alerts.call_args_list[1].kwargs["last_activity_timestamp"]
        == "2026-08-03T10:05:09"
    )


def test_process_message_same_timestamp_pages_then_moves_cursor(doppel_connector):
    connector, helper = doppel_connector
    stored = _record_last_runs(helper)
    timestamp = "2026-08-03T10:15:00.987654Z"
    alerts = [
        {"id": f"alert-{index}", "last_activity_timestamp": timestamp}
        for index in range(250)
    ]
    requested_pages = []

    def get_alerts(**kwargs):
        requested_pages.append(kwargs["page"])
        assert kwargs["last_activity_timestamp"] == "2026-08-03T10:00:00"
        assert kwargs["last_activity_before"] == "2026-08-03T12:00:00"
        assert kwargs["page_size"] == 100
        start = kwargs["page"] * kwargs["page_size"]
        return alerts[start : start + kwargs["page_size"]], 3

    connector.client.get_alerts.side_effect = get_alerts

    connector.process_message()

    assert requested_pages == [0, 1, 2]
    sent_counts = [
        len(call.args[0])
        for call in connector.converter.convert_alerts_to_stix.call_args_list
    ]
    assert sent_counts == [100, 100, 50]
    assert stored == [
        "2026-08-03 10:15:00",
        "2026-08-03 10:15:00",
        "2026-08-03 10:15:00",
        WINDOW_END,
    ]
    helper.api.work.initiate_work.assert_called_once()
    helper.api.work.to_processed.assert_called_once_with(
        "work-1", "Doppel connector successfully run"
    )


def test_process_message_same_timestamp_failure_keeps_page_checkpoint(
    doppel_connector,
):
    connector, helper = doppel_connector
    stored = _record_last_runs(helper)
    timestamp = "2026-08-03T10:15:00.987654Z"
    page = [
        {"id": f"alert-{index}", "last_activity_timestamp": timestamp}
        for index in range(100)
    ]

    def get_alerts(**kwargs):
        if kwargs["page"] == 0:
            assert kwargs["last_activity_timestamp"] == "2026-08-03T10:00:00"
            return page, 3
        raise RuntimeError("page 1 failed")

    connector.client.get_alerts.side_effect = get_alerts

    connector.process_message()

    assert stored == ["2026-08-03 10:15:00"]
    helper.send_stix2_bundle.assert_called_once()
    assert connector.client.get_alerts.call_args_list[1].kwargs["page"] == 1
    assert (
        connector.client.get_alerts.call_args_list[1].kwargs["last_activity_timestamp"]
        == "2026-08-03T10:00:00"
    )
    helper.api.work.to_processed.assert_called_once()
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is True


def test_process_message_short_page_stores_window_end(doppel_connector):
    connector, helper = doppel_connector
    events = []

    def record_state(state):
        events.append(("state", state["last_run"]))

    def record_processed(*_args, **kwargs):
        events.append(("processed", kwargs.get("in_error", False)))

    helper.set_state.side_effect = record_state
    helper.api.work.to_processed.side_effect = record_processed
    connector.client.get_alerts.return_value = (
        [{"id": "only", "last_activity_timestamp": "2026-08-03T11:00:00.123Z"}],
        1,
    )

    connector.process_message()

    assert connector.client.get_alerts.call_count == 1
    call = connector.client.get_alerts.call_args.kwargs
    assert call["page"] == 0
    assert call["last_activity_timestamp"] == "2026-08-03T10:00:00"
    assert call["last_activity_before"] == "2026-08-03T12:00:00"
    assert events == [
        ("state", "2026-08-03 11:00:00"),
        ("state", WINDOW_END),
        ("processed", False),
    ]
    helper.send_stix2_bundle.assert_called_once()


def test_process_message_empty_window_updates_last_run_without_work(doppel_connector):
    connector, helper = doppel_connector
    stored = _record_last_runs(helper)
    connector.client.get_alerts.return_value = ([], 0)

    connector.process_message()

    assert stored == [WINDOW_END]
    helper.api.work.initiate_work.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()
    helper.api.work.to_processed.assert_not_called()
