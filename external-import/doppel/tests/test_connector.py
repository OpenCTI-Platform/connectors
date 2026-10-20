import math
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from doppel.client_api import ResultWindowExceededError
from doppel.connector import DoppelConnector
from doppel.utils import parse_iso_datetime

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


def _fake_alert_server(alerts, requests=None, before_response=None):
    """
    Emulate ``GET /alerts`` over a mutable in-memory alert list.

    Filters by the inclusive activity bounds, sorts by ``last_activity`` then
    ``id`` like the API, pages by offset, and reports ``count`` and
    ``total_pages`` for the whole window. ``before_response`` runs after the
    request is recorded and before the page is computed so a test can mutate
    ``alerts`` between pages.
    """

    def get_alerts(**kwargs):
        request = (
            kwargs["last_activity_timestamp"],
            kwargs["last_activity_before"],
            kwargs["page"],
        )
        if requests is not None:
            requests.append(request)
        if before_response is not None:
            before_response(request)
        start = parse_iso_datetime(kwargs["last_activity_timestamp"])
        end = parse_iso_datetime(kwargs["last_activity_before"])
        matching = sorted(
            (
                alert
                for alert in alerts
                if start <= parse_iso_datetime(alert["last_activity_timestamp"]) <= end
            ),
            key=lambda alert: (
                parse_iso_datetime(alert["last_activity_timestamp"]),
                alert["id"],
            ),
        )
        page_size = kwargs["page_size"]
        offset = kwargs["page"] * page_size
        return (
            matching[offset : offset + page_size],
            math.ceil(len(matching) / page_size),
            len(matching),
        )

    return get_alerts


def _sent_alert_ids(connector):
    return [
        alert["id"]
        for call in connector.converter.convert_alerts_to_stix.call_args_list
        for alert in call.args[0]
    ]


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
            return first_page, 2, 3
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


def test_process_message_validates_checkpoint_before_opencti_side_effects(
    doppel_connector,
):
    connector, helper = doppel_connector
    connector.client.get_alerts.return_value = ([{"id": "missing-activity"}], 1, 1)

    connector.process_message()

    helper.api.work.initiate_work.assert_not_called()
    connector.converter.convert_alerts_to_stix.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()
    helper.set_state.assert_not_called()
    error = helper.connector_logger.error.call_args.args[1]["error"]
    assert isinstance(error, ValueError)
    assert str(error) == "Doppel alerts are missing last_activity_timestamp"


def test_process_message_bisects_oversized_window_until_oldest_range_fits(
    doppel_connector,
):
    connector, helper = doppel_connector
    stored = _record_last_runs(helper)
    requested_windows = []

    def get_alerts(**kwargs):
        requested_windows.append(
            (
                kwargs["last_activity_timestamp"],
                kwargs["last_activity_before"],
                kwargs["page"],
            )
        )
        if kwargs["last_activity_before"] in {
            "2026-08-03T12:00:00",
            "2026-08-03T11:00:00",
        }:
            raise ResultWindowExceededError("Result window exceeds 50000 alerts")
        return (
            [
                {
                    "id": "oldest-alert",
                    "last_activity_timestamp": "2026-08-03T10:15:00Z",
                }
            ],
            1,
            1,
        )

    connector.client.get_alerts.side_effect = get_alerts

    connector.process_message()

    assert requested_windows == [
        ("2026-08-03T10:00:00", "2026-08-03T12:00:00", 0),
        ("2026-08-03T10:00:00", "2026-08-03T11:00:00", 0),
        ("2026-08-03T10:00:00", "2026-08-03T10:30:00", 0),
    ]
    assert stored == [
        "2026-08-03 10:15:00",
        "2026-08-03 10:30:00",
    ]
    helper.send_stix2_bundle.assert_called_once()
    assert helper.connector_logger.warning.call_count == 2
    helper.api.work.to_processed.assert_called_once_with(
        "work-1", "Doppel connector successfully run"
    )


def test_process_message_does_not_loop_when_one_second_window_is_too_large(
    doppel_connector,
):
    connector, helper = doppel_connector
    helper.get_state.return_value = {"last_run": "2026-08-03 11:59:59"}
    connector.client.get_alerts.side_effect = ResultWindowExceededError(
        "Result window exceeds 50000 alerts"
    )

    connector.process_message()

    connector.client.get_alerts.assert_called_once()
    helper.set_state.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()
    helper.api.work.to_processed.assert_not_called()
    helper.connector_logger.error.assert_called_once()


def test_process_message_same_second_drains_bounded_window_then_moves_cursor(
    doppel_connector,
):
    connector, helper = doppel_connector
    stored = _record_last_runs(helper)
    timestamp = "2026-08-03T10:15:00.987654Z"
    alerts = [
        {"id": f"alert-{index:03d}", "last_activity_timestamp": timestamp}
        for index in range(250)
    ]
    alerts.append(
        {"id": "later-alert", "last_activity_timestamp": "2026-08-03T10:20:00Z"}
    )
    requests = []
    connector.client.get_alerts.side_effect = _fake_alert_server(alerts, requests)

    connector.process_message()

    # The wide page that revealed the shared second is discarded; the second is
    # re-read through a one-second window and only then does the cursor move
    # past it.
    assert requests == [
        ("2026-08-03T10:00:00", "2026-08-03T12:00:00", 0),
        ("2026-08-03T10:15:00", "2026-08-03T10:15:01", 0),
        ("2026-08-03T10:15:00", "2026-08-03T10:15:01", 1),
        ("2026-08-03T10:15:00", "2026-08-03T10:15:01", 2),
        ("2026-08-03T10:15:01", "2026-08-03T12:00:00", 0),
    ]
    sent_counts = [
        len(call.args[0])
        for call in connector.converter.convert_alerts_to_stix.call_args_list
    ]
    assert sent_counts == [100, 100, 50, 1]
    assert _sent_alert_ids(connector) == [alert["id"] for alert in alerts]
    assert stored == [
        "2026-08-03 10:15:00",
        "2026-08-03 10:15:00",
        "2026-08-03 10:15:00",
        "2026-08-03 10:20:00",
        WINDOW_END,
    ]
    helper.api.work.initiate_work.assert_called_once()
    helper.api.work.to_processed.assert_called_once_with(
        "work-1", "Doppel connector successfully run"
    )


def test_process_message_same_second_restarts_when_alert_departs_mid_walk(
    doppel_connector,
):
    connector, helper = doppel_connector
    stored = _record_last_runs(helper)
    timestamp = "2026-08-03T10:15:00.500000Z"
    alerts = [
        {"id": f"alert-{index:03d}", "last_activity_timestamp": timestamp}
        for index in range(250)
    ]
    requests = []

    def depart_after_first_narrow_page(request):
        # Between narrow page 0 and page 1, alert-000 (already fetched) gets new
        # activity after the run started. Offset paging alone would now shift
        # alert-100 into page 0 and never fetch it.
        if request == ("2026-08-03T10:15:00", "2026-08-03T10:15:01", 1) and (
            alerts[0]["last_activity_timestamp"] == timestamp
        ):
            alerts[0]["last_activity_timestamp"] = "2026-08-03T12:30:00Z"

    connector.client.get_alerts.side_effect = _fake_alert_server(
        alerts, requests, depart_after_first_narrow_page
    )

    connector.process_message()

    assert requests == [
        ("2026-08-03T10:00:00", "2026-08-03T12:00:00", 0),
        ("2026-08-03T10:15:00", "2026-08-03T10:15:01", 0),
        ("2026-08-03T10:15:00", "2026-08-03T10:15:01", 1),
        ("2026-08-03T10:15:00", "2026-08-03T10:15:01", 0),
        ("2026-08-03T10:15:00", "2026-08-03T10:15:01", 1),
        ("2026-08-03T10:15:00", "2026-08-03T10:15:01", 2),
        ("2026-08-03T10:15:01", "2026-08-03T12:00:00", 0),
    ]
    remaining_ids = {alert["id"] for alert in alerts[1:]}
    assert remaining_ids <= set(_sent_alert_ids(connector))
    assert "alert-100" in _sent_alert_ids(connector)
    assert stored[-1] == WINDOW_END
    assert helper.connector_logger.warning.call_count == 1
    helper.api.work.to_processed.assert_called_once_with(
        "work-1", "Doppel connector successfully run"
    )


def test_process_message_same_second_gives_up_after_repeated_changes(
    doppel_connector,
):
    connector, helper = doppel_connector
    stored = _record_last_runs(helper)
    timestamp = "2026-08-03T10:15:00Z"
    alerts = [
        {"id": f"alert-{index:03d}", "last_activity_timestamp": timestamp}
        for index in range(201)
    ]

    def depart_on_every_second_page(request):
        if request[2] == 1:
            for alert in alerts:
                if alert["last_activity_timestamp"] == timestamp:
                    alert["last_activity_timestamp"] = "2026-08-03T12:30:00Z"
                    break

    connector.client.get_alerts.side_effect = _fake_alert_server(
        alerts, before_response=depart_on_every_second_page
    )

    connector.process_message()

    assert helper.connector_logger.warning.call_count == 3
    error = helper.connector_logger.error.call_args.args[1]["error"]
    assert isinstance(error, RuntimeError)
    assert str(error) == (
        "Doppel alerts kept changing while paging a single activity second"
    )
    # Every stored checkpoint stays on the unfinished second so the next run
    # replays it instead of skipping anything.
    assert stored and set(stored) == {"2026-08-03 10:15:00"}
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is True


def test_process_message_same_second_window_is_clamped_to_window_end(
    doppel_connector,
):
    connector, helper = doppel_connector
    connector.config.doppel.page_size = 2
    stored = _record_last_runs(helper)
    alerts = [
        {"id": f"alert-{index}", "last_activity_timestamp": "2026-08-03T12:00:00Z"}
        for index in range(3)
    ]
    requests = []
    connector.client.get_alerts.side_effect = _fake_alert_server(alerts, requests)

    connector.process_message()

    assert requests == [
        ("2026-08-03T10:00:00", "2026-08-03T12:00:00", 0),
        ("2026-08-03T12:00:00", "2026-08-03T12:00:00", 0),
        ("2026-08-03T12:00:00", "2026-08-03T12:00:00", 1),
    ]
    assert _sent_alert_ids(connector) == ["alert-0", "alert-1", "alert-2"]
    assert stored == [WINDOW_END, WINDOW_END, WINDOW_END]
    helper.api.work.to_processed.assert_called_once_with(
        "work-1", "Doppel connector successfully run"
    )


def test_process_message_same_second_failure_keeps_second_checkpoint(
    doppel_connector,
):
    connector, helper = doppel_connector
    stored = _record_last_runs(helper)
    timestamp = "2026-08-03T10:15:00.987654Z"
    alerts = [
        {"id": f"alert-{index:03d}", "last_activity_timestamp": timestamp}
        for index in range(250)
    ]
    server = _fake_alert_server(alerts)

    def get_alerts(**kwargs):
        if kwargs["page"] == 1:
            raise RuntimeError("page 1 failed")
        return server(**kwargs)

    connector.client.get_alerts.side_effect = get_alerts

    connector.process_message()

    assert stored == ["2026-08-03 10:15:00"]
    helper.send_stix2_bundle.assert_called_once()
    failed_call = connector.client.get_alerts.call_args_list[2].kwargs
    assert failed_call["page"] == 1
    assert failed_call["last_activity_timestamp"] == "2026-08-03T10:15:00"
    assert failed_call["last_activity_before"] == "2026-08-03T10:15:01"
    helper.api.work.to_processed.assert_called_once()
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is True


def test_process_message_same_second_window_error_preserves_original_cause(
    doppel_connector,
):
    connector, helper = doppel_connector
    connector.config.doppel.page_size = 1
    result_window_error = ResultWindowExceededError(
        "Result window exceeds 50000 alerts"
    )
    connector.client.get_alerts.side_effect = [
        (
            [
                {
                    "id": "same-timestamp",
                    "last_activity_timestamp": "2026-08-03T10:15:00Z",
                }
            ],
            2,
            2,
        ),
        result_window_error,
    ]

    connector.process_message()

    helper.send_stix2_bundle.assert_not_called()
    helper.set_state.assert_not_called()
    error = helper.connector_logger.error.call_args.args[1]["error"]
    assert isinstance(error, RuntimeError)
    assert error.__cause__ is result_window_error
    helper.api.work.to_processed.assert_called_once()
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is True


def test_process_message_rejects_alerts_older_than_cursor(doppel_connector):
    connector, helper = doppel_connector
    connector.client.get_alerts.return_value = (
        [{"id": "stale", "last_activity_timestamp": "2026-08-03T09:00:00Z"}],
        1,
        1,
    )

    connector.process_message()

    connector.client.get_alerts.assert_called_once()
    helper.send_stix2_bundle.assert_not_called()
    helper.set_state.assert_not_called()
    error = helper.connector_logger.error.call_args.args[1]["error"]
    assert isinstance(error, ValueError)
    assert str(error) == (
        "Doppel returned alerts older than the requested activity window"
    )


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
    connector.client.get_alerts.return_value = ([], 0, 0)

    connector.process_message()

    assert stored == [WINDOW_END]
    helper.api.work.initiate_work.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()
    helper.api.work.to_processed.assert_not_called()
