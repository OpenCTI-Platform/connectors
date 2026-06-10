from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

from connector.connector import FlareConnector


def _make_connector(
    event_types: list[str] | None = None,
    event_actions: list[str] | None = None,
    lookback_days: int = 30,
) -> tuple[FlareConnector, MagicMock, MagicMock, MagicMock]:
    config = MagicMock()
    config.connector_duration_period = "PT1H"
    config.flare_lookback_days = lookback_days
    config.flare_event_types = (
        event_types if event_types is not None else ["stealer_log"]
    )
    config.flare_event_actions = event_actions
    helper = MagicMock()
    flare_client = MagicMock()
    mapper = MagicMock()
    connector = FlareConnector(
        config=config, helper=helper, flare_client=flare_client, mapper=mapper
    )
    return connector, helper, flare_client, mapper


def test_schedules_with_correct_params() -> None:
    connector, helper, _, _ = _make_connector()
    connector.run()
    helper.schedule_process.assert_called_once_with(
        message_callback=connector.process_message,
        duration_period=3600.0,
    )


class TestProcessMessage:
    def test_first_run_no_state(self) -> None:
        connector, helper, flare_client, _ = _make_connector(lookback_days=7)
        helper.get_state.return_value = None
        captured: list[datetime] = []

        def capture_and_return(from_date: datetime, **_: Any) -> Any:
            captured.append(from_date)
            return iter([])

        flare_client.get_events.side_effect = capture_and_return

        connector.process_message()

        assert len(captured) == 1
        expected = datetime.now(timezone.utc) - timedelta(days=7)
        assert abs((captured[0] - expected).total_seconds()) < 5

    def test_first_run_missing_last_run_key(self) -> None:
        connector, helper, flare_client, _ = _make_connector(lookback_days=14)
        helper.get_state.return_value = {}
        captured: list[datetime] = []

        def capture_and_return(from_date: datetime, **_: Any) -> Any:
            captured.append(from_date)
            return iter([])

        flare_client.get_events.side_effect = capture_and_return

        connector.process_message()

        assert len(captured) == 1
        expected = datetime.now(timezone.utc) - timedelta(days=14)
        assert abs((captured[0] - expected).total_seconds()) < 5

    def test_incremental_run_uses_last_run(self) -> None:
        connector, helper, flare_client, _ = _make_connector()
        last_run_iso = "2025-06-01T12:00:00+00:00"
        helper.get_state.return_value = {"last_run": last_run_iso}
        captured: list[datetime] = []

        def capture_and_return(from_date: datetime, **_: Any) -> Any:
            captured.append(from_date)
            return iter([])

        flare_client.get_events.side_effect = capture_and_return

        connector.process_message()

        assert captured[0] == datetime.fromisoformat(last_run_iso)

    def test_sets_state_after_sync(self) -> None:
        connector, helper, flare_client, _ = _make_connector()
        helper.get_state.return_value = None
        flare_client.get_events.return_value = iter([])

        connector.process_message()

        helper.set_state.assert_called_once()
        state_arg = helper.set_state.call_args[0][0]
        assert "last_run" in state_arg

    def test_initiates_and_completes_work(self) -> None:
        connector, helper, flare_client, _ = _make_connector()
        helper.get_state.return_value = None
        flare_client.get_events.return_value = iter([])
        helper.api.work.initiate_work.return_value = "work-123"

        connector.process_message()

        helper.api.work.initiate_work.assert_called_once_with(
            helper.connect_id, "Flare sync"
        )
        helper.api.work.to_processed.assert_called_once()

    def test_exception_marks_work_as_error(self) -> None:
        connector, helper, flare_client, _ = _make_connector()
        helper.get_state.return_value = None
        helper.api.work.initiate_work.return_value = "work-123"
        flare_client.get_events.side_effect = RuntimeError("boom")

        # Should not raise
        connector.process_message()

        helper.connector_logger.error.assert_called()
        helper.api.work.to_processed.assert_called_once_with(
            "work-123", "boom", in_error=True
        )

    def test_exception_before_initiate_work_does_not_call_to_processed(self) -> None:
        connector, helper, _, _ = _make_connector()
        helper.get_state.side_effect = RuntimeError("state error")

        connector.process_message()

        helper.api.work.to_processed.assert_not_called()


class TestProcessEvents:
    def test_empty_events_returns_zero(self) -> None:
        connector, _, _, _ = _make_connector()
        assert connector.process_events(iter([]), work_id=None) == 0

    def test_happy_path_returns_count(self) -> None:
        connector, helper, _, mapper = _make_connector()
        incident = MagicMock()
        incident.name = "Test Incident"
        mapper.map_event_to_incident.return_value = (incident, [MagicMock()])
        mapper.author = MagicMock()
        helper.stix2_create_bundle.return_value = MagicMock()

        events = [{"id": "e1"}, {"id": "e2"}]
        result = connector.process_events(iter(events), work_id="work-123")

        assert result == 2
        assert helper.send_stix2_bundle.call_count == 2

    def test_bundle_sent_with_work_id_and_cleanup(self) -> None:
        connector, helper, _, mapper = _make_connector()
        incident = MagicMock()
        incident.name = "Test"
        mapper.map_event_to_incident.return_value = (incident, [])
        mapper.author = MagicMock()
        helper.stix2_create_bundle.return_value = MagicMock()

        connector.process_events(iter([{"id": "e1"}]), work_id="work-123")

        helper.send_stix2_bundle.assert_called_once()
        call_kwargs = helper.send_stix2_bundle.call_args[1]
        assert call_kwargs["work_id"] == "work-123"
        assert call_kwargs["cleanup_inconsistent_bundle"] is True

    def test_null_bundle_skips_event(self) -> None:
        connector, helper, _, mapper = _make_connector()
        incident = MagicMock()
        incident.name = "Test"
        mapper.map_event_to_incident.return_value = (incident, [])
        mapper.author = MagicMock()
        helper.stix2_create_bundle.return_value = None

        result = connector.process_events(iter([{"id": "e1"}]), work_id=None)

        assert result == 0
        helper.send_stix2_bundle.assert_not_called()
        helper.connector_logger.error.assert_called()

    def test_mapper_exception_skips_event_and_continues(self) -> None:
        connector, helper, _, mapper = _make_connector()
        good_incident = MagicMock()
        good_incident.name = "Good"
        mapper.map_event_to_incident.side_effect = [
            RuntimeError("parse error"),
            (good_incident, []),
        ]
        mapper.author = MagicMock()
        helper.stix2_create_bundle.return_value = MagicMock()

        result = connector.process_events(
            iter([{"id": "e1"}, {"id": "e2"}]), work_id=None
        )

        assert result == 1
        helper.connector_logger.error.assert_called()
