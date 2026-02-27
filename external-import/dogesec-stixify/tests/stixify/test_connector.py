import json
from unittest.mock import MagicMock, call

import freezegun
import pytest
from connector import StixifyConnector
from pytest_mock import MockerFixture


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_connector_init(
    mocked_helper: MagicMock, mock_session: MagicMock, mock_config
) -> None:
    """Test connector initialization"""
    connector = StixifyConnector()

    assert connector.base_url == "https://test-stixify-url/"
    assert connector.api_key == "test-api-key"
    assert connector.dossier_ids == ["dossier-1", "dossier-2"]
    assert connector.interval_hours == 1
    assert connector.session.headers == {"API-KEY": "test-api-key"}


@pytest.fixture
def connector(mocked_helper, mock_session: MagicMock, mock_config) -> StixifyConnector:
    """Fixture for StixifyConnector instance"""
    return StixifyConnector()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_connector_run(connector: StixifyConnector) -> None:
    """Test connector run method"""
    connector.run()

    assert connector.helper.log_info.call_count == 1
    connector.helper.log_info.assert_has_calls([call("Starting Stixify")])

    assert connector.helper.schedule_process.call_count == 1
    connector.helper.schedule_process.assert_called_once_with(
        message_callback=connector.run_once, duration_period=3600
    )


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_get_state_empty(connector: StixifyConnector) -> None:
    """Test _get_state with empty state"""
    connector.helper.get_state.return_value = None

    state = connector._get_state()

    assert state == {"dossiers": {}}
    connector.helper.get_state.assert_called_once()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_get_state_existing(connector: StixifyConnector) -> None:
    """Test _get_state with existing state"""
    existing_state = {
        "dossiers": {"dossier-1": {"last_run_at": "2026-02-17T15:24:00Z"}},
        "last_run": "2026-02-17T15:24:00Z",
    }
    connector.helper.get_state.return_value = existing_state
    state = connector._get_state()

    assert state == existing_state
    connector.helper.get_state.assert_called_once()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_set_dossier_state(connector: StixifyConnector) -> None:
    """Test set_dossier_state method"""
    connector.helper.get_state.return_value = {"dossiers": {}}

    connector.set_dossier_state("dossier-1", "2026-02-18T15:24:00Z")

    expected_state = {
        "dossiers": {"dossier-1": {"last_run_at": "2026-02-18T15:24:00Z"}},
    }
    connector.helper.set_state.assert_called_once_with(expected_state)


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_list_dossiers_success(
    connector: StixifyConnector, mock_session: MagicMock
) -> None:
    """Test list_dossiers success"""
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "results": [
            {"id": "dossier-1", "name": "Dossier One"},
            {"id": "dossier-2", "name": "Dossier Two"},
        ],
        "total_results_count": 2,
    }
    mock_session.get.return_value = mock_response

    dossiers = connector.list_dossiers()

    assert len(dossiers) == 2
    assert dossiers[0]["id"] == "dossier-1"
    assert dossiers[1]["id"] == "dossier-2"


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_retrieve(connector: StixifyConnector, mock_session: MagicMock) -> None:
    """Test retrieve method with pagination"""
    mock_response_1 = MagicMock()
    mock_response_1.json.return_value = {
        "total_results_count": 3,
        "objects": [{"id": "obj-1"}, {"id": "obj-2"}],
    }

    mock_response_2 = MagicMock()
    mock_response_2.json.return_value = {
        "total_results_count": 3,
        "objects": [{"id": "obj-3"}],
    }

    mock_session.get.side_effect = [mock_response_1, mock_response_2]

    objects = connector.retrieve("v1/test/", list_key="objects")

    assert len(objects) == 3
    assert objects[0]["id"] == "obj-1"
    assert objects[2]["id"] == "obj-3"


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_process_report_success(
    connector: StixifyConnector, mock_session: MagicMock
) -> None:
    """Test process_report success"""
    report = {
        "id": "report-1",
        "name": "Test Report",
        "created_at": "2026-02-18T15:24:00Z",
    }

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "total_results_count": 2,
        "objects": [
            {"type": "indicator", "id": "indicator--1"},
            {"type": "indicator", "id": "indicator--2"},
        ],
    }
    mock_session.get.return_value = mock_response

    connector.process_report(report, "work-id")

    connector.helper.send_stix2_bundle.assert_called_once()
    bundle_arg = connector.helper.send_stix2_bundle.call_args[0][0]
    bundle = json.loads(bundle_arg)

    assert bundle["type"] == "bundle"
    assert bundle["id"] == "bundle--report-1"
    assert len(bundle["objects"]) == 2


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_run_once(mocker: MockerFixture, connector: StixifyConnector) -> None:
    """Test run_once method"""
    mock_dossiers = [
        {"id": "dossier-1", "name": "Dossier One"},
        {"id": "dossier-2", "name": "Dossier Two"},
    ]
    mocker.patch.object(connector, "list_dossiers", return_value=mock_dossiers)

    get_reports_mock = mocker.patch.object(
        connector, "get_and_process_reports_after_last"
    )

    connector.run_once()

    connector.helper.api.work.initiate_work.assert_called()
    assert get_reports_mock.call_count == 2
    connector.helper.api.work.to_processed.assert_called()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_run_once_filters_dossiers(
    mocker: MockerFixture, connector: StixifyConnector
) -> None:
    """Test run_once filters dossiers based on config"""
    mock_dossiers = [
        {"id": "dossier-1", "name": "Dossier One"},
        {"id": "dossier-2", "name": "Dossier Two"},
        {"id": "dossier-3", "name": "Dossier Three"},  # Not in config
    ]
    mocker.patch.object(connector, "list_dossiers", return_value=mock_dossiers)

    get_reports_mock = mocker.patch.object(
        connector, "get_and_process_reports_after_last"
    )
    mocker.patch.object(connector, "set_dossier_state")

    connector.run_once()

    assert get_reports_mock.call_count == 2


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_run_in_work_success(connector: StixifyConnector) -> None:
    """Test _run_in_work context manager success"""
    with connector._run_in_work("Test Work") as work_id:
        assert work_id == "work-id"

    connector.helper.api.work.initiate_work.assert_called_once_with(
        "connector-id", "Test Work"
    )
    connector.helper.api.work.to_processed.assert_called_once_with(
        work_id="work-id", message="[Stixify] Work done", in_error=False
    )


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_run_in_work_failure(connector: StixifyConnector) -> None:
    """Test _run_in_work context manager failure"""
    with connector._run_in_work("Test Work"):
        raise ValueError("Test error")

    call_kwargs = connector.helper.api.work.to_processed.call_args[1]
    assert call_kwargs["in_error"] is True
    assert "[Stixify] Work failed" in call_kwargs["message"]
    assert "ValueError: Test error" in call_kwargs["message"]


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_get_param(connector: StixifyConnector) -> None:
    """Test _get_param method"""

    result = connector._get_param("base_url")
    assert result == "https://test-stixify-url/"

    result = connector._get_param("interval_hours", is_number=True)
    assert result == 1
    assert isinstance(result, int)
