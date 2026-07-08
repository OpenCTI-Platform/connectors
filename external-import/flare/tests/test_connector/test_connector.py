from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest
from connector.connector import FlareConnector


def _make_connector(
    event_types: list[str] | None = None,
    event_actions: list[str] | None = None,
    lookback_days: int = 30,
) -> tuple[FlareConnector, MagicMock, MagicMock, MagicMock]:
    config = MagicMock()
    config.connector.duration_period.total_seconds.return_value = 3600.0
    config.flare.lookback_days = lookback_days
    config.flare.event_types = (
        event_types if event_types is not None else ["stealer_log"]
    )
    config.flare.event_actions = event_actions
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


class TestProcessMessageFlow:
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
        connector, helper, flare_client, mapper = _make_connector()
        helper.get_state.return_value = None
        helper.api.work.initiate_work.return_value = "work-123"
        incident = MagicMock()
        incident.name = "Test"
        mapper.map_event_to_incident.return_value = (incident, [])
        mapper.author = MagicMock()
        helper.stix2_create_bundle.return_value = MagicMock()
        flare_client.get_events.return_value = iter([{"id": "e1"}])

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

        with pytest.raises(RuntimeError):
            connector.process_message()

        helper.connector_logger.error.assert_called()

    def test_exception_before_initiate_work_does_not_call_to_processed(self) -> None:
        connector, helper, _, _ = _make_connector()
        helper.get_state.side_effect = RuntimeError("state error")

        with pytest.raises(RuntimeError):
            connector.process_message()

        helper.api.work.to_processed.assert_not_called()


class TestProcessEventsFlow:
    def test_empty_events_returns_zero(self) -> None:
        connector, _, _, _ = _make_connector()
        assert connector.process_events(iter([])) == 0

    def test_happy_path_returns_count(self) -> None:
        connector, helper, _, mapper = _make_connector()
        incident = MagicMock()
        incident.name = "Test Incident"
        mapper.map_event_to_incident.return_value = (incident, [MagicMock()])
        mapper.author = MagicMock()
        helper.stix2_create_bundle.return_value = MagicMock()

        events = [{"id": "e1"}, {"id": "e2"}]
        connector.work_id = "work-123"
        result = connector.process_events(iter(events))

        assert result == 2
        assert helper.send_stix2_bundle.call_count == 2

    def test_bundle_sent_with_work_id_and_cleanup(self) -> None:
        connector, helper, _, mapper = _make_connector()
        incident = MagicMock()
        incident.name = "Test"
        mapper.map_event_to_incident.return_value = (incident, [])
        mapper.author = MagicMock()
        helper.stix2_create_bundle.return_value = MagicMock()

        connector.process_events(iter([{"id": "e1"}]))

        helper.send_stix2_bundle.assert_called_once()
        call_kwargs = helper.send_stix2_bundle.call_args[1]
        assert call_kwargs["work_id"] == connector.work_id
        assert call_kwargs["cleanup_inconsistent_bundle"] is True

    def test_null_bundle_skips_event(self) -> None:
        connector, helper, _, mapper = _make_connector()
        incident = MagicMock()
        incident.name = "Test"
        mapper.map_event_to_incident.return_value = (incident, [])
        mapper.author = MagicMock()
        helper.stix2_create_bundle.return_value = None

        result = connector.process_events(iter([{"id": "e1"}]))

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

        result = connector.process_events(iter([{"id": "e1"}, {"id": "e2"}]))

        assert result == 1
        helper.connector_logger.error.assert_called()


@pytest.fixture
def mock_config() -> MagicMock:
    config = MagicMock()
    config.connector.duration_period = timedelta(hours=1)
    config.flare.lookback_days = 30
    config.flare.event_types = ["stealer_log"]
    config.flare.event_actions = []
    return config


@pytest.fixture
def mock_helper() -> MagicMock:
    helper = MagicMock()
    helper.connect_id = "test-connect-id"
    return helper


@pytest.fixture
def mock_flare_client() -> MagicMock:
    return MagicMock()


@pytest.fixture
def mock_mapper() -> MagicMock:
    mapper = MagicMock()
    mapper.author = MagicMock()
    mapper.tlp_level = MagicMock()
    return mapper


@pytest.fixture
def connector(
    mock_config: MagicMock,
    mock_helper: MagicMock,
    mock_flare_client: MagicMock,
    mock_mapper: MagicMock,
) -> FlareConnector:
    return FlareConnector(mock_config, mock_helper, mock_flare_client, mock_mapper)


class TestRun:
    def test_logs_debug_message_and_schedules_process(
        self, connector: FlareConnector, mock_helper: MagicMock, mock_config: MagicMock
    ) -> None:
        connector.run()

        mock_helper.connector_logger.debug.assert_called_once()
        mock_helper.schedule_process.assert_called_once_with(
            message_callback=connector.process_message,
            duration_period=mock_config.connector.duration_period.total_seconds(),
        )


class TestProcessMessage:
    def test_logs_and_raises_unexpected_errors(
        self, connector: FlareConnector, mock_helper: MagicMock
    ) -> None:
        mock_helper.get_state.side_effect = RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            connector.process_message()

        mock_helper.connector_logger.error.assert_called_once()

    @pytest.mark.parametrize(
        "current_state",
        [
            pytest.param(None, id="no_state"),
            pytest.param({"last_run": "2025-01-01T00:00:00Z"}, id="string_date"),
            pytest.param(
                {"last_run": datetime.fromisoformat("2025-01-01T00:00:00Z")},
                id="datetime_object",
            ),
        ],
    )
    def test_from_date_parsing(
        self,
        current_state: dict[str, str | datetime] | None,
        connector: FlareConnector,
        mock_helper: MagicMock,
        mock_flare_client: MagicMock,
    ) -> None:
        mock_helper.get_state.return_value = current_state
        mock_flare_client.get_events.return_value = iter([])

        connector.process_message()

        from_date = mock_flare_client.get_events.call_args[0][0]
        last_run_raw = (current_state or {}).get("last_run")

        if isinstance(last_run_raw, str):
            assert from_date == datetime.fromisoformat(
                last_run_raw.replace("Z", "+00:00")
            )
        else:
            expected = datetime.now(timezone.utc) - timedelta(
                days=connector.config.flare.lookback_days
            )
            assert abs((from_date - expected).total_seconds()) < 2

    def test_sends_message_with_success(
        self,
        connector: FlareConnector,
        mock_helper: MagicMock,
        mock_flare_client: MagicMock,
    ) -> None:
        mock_helper.get_state.return_value = None
        mock_flare_client.get_events.return_value = iter([])

        connector.process_message()

        mock_helper.set_state.assert_called_once()
        state_arg = mock_helper.set_state.call_args[0][0]
        assert "last_run" in state_arg
        assert isinstance(state_arg["last_run"], str)
        mock_helper.api.work.to_processed.assert_not_called()


class TestProcessEvents:
    def test_logs_import_errors(
        self, connector: FlareConnector, mock_helper: MagicMock, mock_mapper: MagicMock
    ) -> None:
        result = connector.process_events(iter([{"data": {"uid": "uid-1"}}]))

        assert result == 0
        mock_helper.connector_logger.error.assert_called_once()

    def test_logs_when_bundle_is_none(
        self, connector: FlareConnector, mock_helper: MagicMock, mock_mapper: MagicMock
    ) -> None:
        incident = MagicMock(name="test-incident")
        mock_mapper.map_event_to_incident.return_value = (incident, [])
        mock_helper.stix2_create_bundle.return_value = None

        result = connector.process_events(iter([{"data": {"uid": "uid-1"}}]))

        assert result == 0
        mock_helper.connector_logger.error.assert_called_once()

    def test_sends_stix2_bundle_with_success(
        self, connector: FlareConnector, mock_helper: MagicMock, mock_mapper: MagicMock
    ) -> None:
        incident = MagicMock(name="test-incident")
        mock_mapper.map_event_to_incident.return_value = (incident, [])
        mock_helper.stix2_create_bundle.return_value = MagicMock()
        events = [{"data": {"uid": "uid-1"}}, {"data": {"uid": "uid-2"}}]

        result = connector.process_events(iter(events))

        assert result == 2
        assert mock_helper.send_stix2_bundle.call_count == 2
