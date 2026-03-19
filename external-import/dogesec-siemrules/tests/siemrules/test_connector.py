import json
from unittest.mock import MagicMock, call

import freezegun
import pytest
from connector import SiemrulesConnector, SiemrulesException
from pytest_mock import MockerFixture


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_connector_init(
    mocked_helper: MagicMock, mock_session: MagicMock, mock_config
) -> None:
    """Test connector initialization"""
    connector = SiemrulesConnector()

    assert connector.base_url == "https://test-siemrules-url/"
    assert connector.api_key == "test-api-key"
    assert connector.detection_packs == ["pack-1", "pack-2"]
    assert connector.interval_hours == 1
    assert connector.session.headers == {"API-KEY": "test-api-key"}


@pytest.fixture
def connector(
    mocked_helper, mock_session: MagicMock, mock_config
) -> SiemrulesConnector:
    """Fixture for SiemrulesConnector instance"""
    return SiemrulesConnector()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_connector_run(connector: SiemrulesConnector) -> None:
    """Test connector run method"""
    connector.run()

    assert connector.helper.log_info.call_count == 1
    connector.helper.log_info.assert_has_calls([call("Starting Siemrules")])

    assert connector.helper.schedule_process.call_count == 1


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_get_state_empty(connector: SiemrulesConnector) -> None:
    """Test _get_state with empty state"""
    connector.helper.get_state.return_value = None

    state = connector._get_state()

    assert state == {"detection-packs": {}}


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_get_state_existing(connector: SiemrulesConnector) -> None:
    """Test _get_state with existing state"""
    existing_state = {
        "detection-packs": {"pack-1": {"latest_update": "2026-02-17T15:24:00Z"}},
        "last_run_start": "2026-02-17T15:24:00Z",
    }
    connector.helper.get_state.return_value = existing_state

    state = connector._get_state()

    assert state == existing_state


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_update_pack_state(connector: SiemrulesConnector) -> None:
    """Test update_pack_state method"""
    connector.helper.get_state.return_value = {"detection-packs": {}}

    connector.update_pack_state("pack-1", latest_update="2026-02-18T15:24:00Z")

    expected_state = {
        "detection-packs": {"pack-1": {"latest_update": "2026-02-18T15:24:00Z"}}
    }
    connector.helper.set_state.assert_called_once_with(expected_state)


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_update_state(connector: SiemrulesConnector) -> None:
    """Test update_state method"""
    connector.helper.get_state.return_value = {"detection-packs": {}}

    connector.update_state(last_run_start="2026-02-18T15:24:00Z")

    expected_state = {
        "detection-packs": {},
        "last_run_start": "2026-02-18T15:24:00Z",
    }
    connector.helper.set_state.assert_called_once_with(expected_state)


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_list_detection_packs_success(
    mock_session: MagicMock, connector: SiemrulesConnector
) -> None:
    """Test list_detection_packs success"""
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "total_results_count": 2,
        "results": [
            {"id": "pack-1", "name": "Pack One"},
            {"id": "pack-2", "name": "Pack Two"},
        ],
    }
    mock_session.get.return_value = mock_response

    packs = connector.list_detection_packs()

    assert len(packs) == 2
    assert packs[0]["id"] == "pack-1"


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_list_detection_packs_failure(
    mock_session: MagicMock, connector: SiemrulesConnector
) -> None:
    """Test list_detection_packs failure"""
    mock_session.get.side_effect = Exception("API Error")

    with pytest.raises(SiemrulesException, match="failed to fetch detection-packs"):
        connector.list_detection_packs()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_retrieve(mock_session: MagicMock, connector: SiemrulesConnector) -> None:
    """Test retrieve method with pagination"""
    # Mock two pages of results
    mock_response_1 = MagicMock()
    mock_response_1.json.return_value = {
        "total_results_count": 3,
        "results": [{"id": "rule-1"}, {"id": "rule-2"}],
    }

    mock_response_2 = MagicMock()
    mock_response_2.json.return_value = {
        "total_results_count": 3,
        "results": [{"id": "rule-3"}],
    }

    mock_session.get.side_effect = [mock_response_1, mock_response_2]

    objects = connector.retrieve("v1/test/", list_key="results")

    assert len(objects) == 3
    assert objects[0]["id"] == "rule-1"
    assert objects[2]["id"] == "rule-3"
    assert mock_session.get.call_count == 2


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_process_rule_success(
    mock_session: MagicMock, connector: SiemrulesConnector
) -> None:
    """Test process_rule success"""
    rule = {
        "metadata": {
            "id": "rule-1",
            "name": "Test Rule",
            "modified": "2026-02-18T15:24:00Z",
        },
        "rule_type": "correlation",
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

    connector.process_rule("pack-1", rule, "work-id")

    connector.helper.send_stix2_bundle.assert_called_once()
    bundle_arg = connector.helper.send_stix2_bundle.call_args[0][0]
    bundle = json.loads(bundle_arg)

    assert bundle["type"] == "bundle"
    assert bundle["id"] == "bundle--rule-1"


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_process_rule_base_type(
    mock_session: MagicMock, connector: SiemrulesConnector
) -> None:
    """Test process_rule with base rule type"""
    rule = {
        "metadata": {
            "id": "rule-1",
            "name": "Test Rule",
            "modified": "2026-02-18T15:24:00Z",
        },
        "rule_type": "base",
    }

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "total_results_count": 1,
        "objects": [{"type": "indicator", "id": "indicator--1"}],
    }
    mock_session.get.return_value = mock_response

    connector.process_rule("pack-1", rule, "work-id")

    # Verify it called the base-rules endpoint
    call_args = mock_session.get.call_args[0][0]
    assert "v1/base-rules/rule-1/objects/" in call_args


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_process_updated_rules(
    mocker: MockerFixture, mock_session: MagicMock, connector: SiemrulesConnector
) -> None:
    """Test process_updated_rules method"""
    connector.helper.get_state.return_value = {"detection-packs": {}}

    dpack = {"id": "pack-1", "name": "Pack One"}

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "total_results_count": 2,
        "results": [
            {
                "metadata": {
                    "id": "rule-1",
                    "name": "Rule 1",
                    "modified": "2026-02-18T15:00:00Z",
                },
                "rule_type": "correlation",
            },
            {
                "metadata": {
                    "id": "rule-2",
                    "name": "Rule 2",
                    "modified": "2026-02-18T15:01:00Z",
                },
                "rule_type": "correlation",
            },
        ],
    }
    mock_session.get.return_value = mock_response

    process_rule_mock = mocker.patch.object(connector, "process_rule")

    connector.process_updated_rules(dpack, "work-id")

    assert process_rule_mock.call_count == 2


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_run_once(mocker: MockerFixture, connector: SiemrulesConnector) -> None:
    """Test run_once method"""
    mock_packs = [
        {"id": "pack-1", "name": "Pack One"},
        {"id": "pack-2", "name": "Pack Two"},
    ]
    mocker.patch.object(connector, "list_detection_packs", return_value=mock_packs)
    mocker.patch.object(connector, "process_updated_rules")
    mocker.patch.object(connector, "update_pack_state")
    mocker.patch.object(connector, "update_state")

    connector.run_once()

    connector.helper.api.work.initiate_work.assert_called()
    connector.helper.api.work.to_processed.assert_called()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_run_in_work_success(connector: SiemrulesConnector) -> None:
    """Test _run_in_work context manager success"""
    with connector._run_in_work("Test Work") as work_id:
        assert work_id == "work-id"

    connector.helper.api.work.to_processed.assert_called_once_with(
        work_id="work-id", message="[SIEMRULES] Work done", in_error=False
    )


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_run_in_work_failure(connector: SiemrulesConnector) -> None:
    """Test _run_in_work context manager failure"""
    with connector._run_in_work("Test Work"):
        raise ValueError("Test error")

    call_kwargs = connector.helper.api.work.to_processed.call_args[1]
    assert call_kwargs["in_error"] is True
    assert "[SIEMRULES] Work failed" in call_kwargs["message"]
    assert "ValueError: Test error" in call_kwargs["message"]
