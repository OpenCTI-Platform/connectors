from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from connector.connector import FlareConnector


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
        mock_helper.api.work.initiate_work.return_value = "work-123"

        connector.process_message()

        mock_helper.set_state.assert_called_once()
        state_arg = mock_helper.set_state.call_args[0][0]
        assert "last_run" in state_arg
        assert isinstance(state_arg["last_run"], str)
        mock_helper.api.work.to_processed.assert_called_once_with(
            "work-123", "Sync completed. Imported 0 events."
        )


class TestProcessEvents:
    def test_logs_import_errors(
        self, connector: FlareConnector, mock_helper: MagicMock, mock_mapper: MagicMock
    ) -> None:
        mock_mapper.map_event_to_incident.side_effect = ValueError("bad event")

        result = connector.process_events(
            iter([{"data": {"uid": "uid-1"}}]), "work-123"
        )

        assert result == 0
        mock_helper.connector_logger.error.assert_called_once()

    def test_logs_when_bundle_is_none(
        self, connector: FlareConnector, mock_helper: MagicMock, mock_mapper: MagicMock
    ) -> None:
        incident = MagicMock(name="test-incident")
        mock_mapper.map_event_to_incident.return_value = (incident, [])
        mock_helper.stix2_create_bundle.return_value = None

        result = connector.process_events(
            iter([{"data": {"uid": "uid-1"}}]), "work-123"
        )

        assert result == 0
        mock_helper.connector_logger.error.assert_called_once()

    def test_sends_stix2_bundle_with_success(
        self, connector: FlareConnector, mock_helper: MagicMock, mock_mapper: MagicMock
    ) -> None:
        incident = MagicMock(name="test-incident")
        mock_mapper.map_event_to_incident.return_value = (incident, [])
        mock_helper.stix2_create_bundle.return_value = MagicMock()
        events = [{"data": {"uid": "uid-1"}}, {"data": {"uid": "uid-2"}}]

        result = connector.process_events(iter(events), "work-123")

        assert result == 2
        assert mock_helper.send_stix2_bundle.call_count == 2
