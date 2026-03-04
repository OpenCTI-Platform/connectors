from unittest.mock import MagicMock, call

import freezegun
import pytest
from connector import (
    CTIButlerConnector,
    KnowledgeBaseIsEmpty,
    VersionAlreadyIngested,
    parse_knowledgebases,
)
from pytest_mock import MockerFixture


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_connector_init(
    mocked_helper: MagicMock, mock_session: MagicMock, mock_config
) -> None:
    """Test connector initialization"""
    connector = CTIButlerConnector()

    assert connector.base_url == "https://test-ctibutler-url/"
    assert connector.api_key == "test-api-key"
    assert connector.knowledgebases == ["cwe", "capec"]
    assert connector.interval_days == 1
    assert connector.session.headers == {"API-KEY": "test-api-key"}


@pytest.fixture
def connector(
    mocked_helper, mock_session: MagicMock, mock_config
) -> CTIButlerConnector:
    """Fixture for CTIButlerConnector instance"""
    return CTIButlerConnector()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_connector_run(connector: CTIButlerConnector) -> None:
    """Test connector run method"""
    connector.run()

    assert connector.helper.log_info.call_count == 1
    connector.helper.log_info.assert_has_calls([call("Starting CTIButler")])

    assert connector.helper.schedule_process.call_count == 1
    connector.helper.schedule_process.assert_called_once_with(
        message_callback=connector.run_once, duration_period=86400
    )


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_parse_knowledgebases_valid(connector: CTIButlerConnector) -> None:
    """Test parse_knowledgebases with valid input"""
    result = parse_knowledgebases(connector.helper, "cwe,capec,atlas")
    assert result == ["cwe", "capec", "atlas"]


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_parse_knowledgebases_invalid(connector: CTIButlerConnector) -> None:
    """Test parse_knowledgebases with invalid input"""
    with pytest.raises(ValueError, match="Unsupported knowledge base: invalid"):
        parse_knowledgebases(connector.helper, "cwe,invalid")


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_get_state_empty(connector: CTIButlerConnector) -> None:
    """Test _get_state with empty state"""
    connector.helper.get_state.return_value = None

    state = connector._get_state()

    assert state == {"versions": {}}


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_get_state_existing(connector: CTIButlerConnector) -> None:
    """Test _get_state with existing state"""
    existing_state = {
        "versions": {"cwe": ["1.0"]},
        "updated": "2026-02-17T15:24:00Z",
    }
    connector.helper.get_state.return_value = existing_state

    state = connector._get_state()

    assert state == existing_state


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_get_knowledge_base_versions(connector: CTIButlerConnector) -> None:
    """Test get_knowledge_base_versions method"""
    connector.helper.get_state.return_value = {"versions": {"cwe": ["1.0"]}}

    state, versions = connector.get_knowledge_base_versions("cwe")

    assert versions == ["1.0"]
    assert state["versions"]["cwe"] == ["1.0"]


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_update_state(connector: CTIButlerConnector) -> None:
    """Test update_state method"""
    connector.helper.get_state.return_value = {"versions": {}}

    connector.update_state("cwe", "1.0")

    expected_call = connector.helper.set_state.call_args[0][0]
    assert expected_call["versions"]["cwe"] == ["1.0"]
    assert "updated" in expected_call


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_retrieve(mock_session: MagicMock, connector: CTIButlerConnector) -> None:
    """Test retrieve method with pagination"""
    # Mock two pages of results
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
    assert mock_session.get.call_count == 2


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_get_knowledge_base_objects_success(
    mock_session: MagicMock, connector: CTIButlerConnector
) -> None:
    """Test get_knowledge_base_objects success"""
    connector.helper.get_state.return_value = {"versions": {}}

    mock_response_versions = MagicMock()
    mock_response_versions.json.return_value = {"versions": ["1.0"]}
    mock_response_versions.raise_for_status = MagicMock()

    mock_response_objects = MagicMock()
    mock_response_objects.json.return_value = {
        "total_results_count": 2,
        "objects": [{"id": "obj-1"}, {"id": "obj-2"}],
    }

    mock_session.get.side_effect = [mock_response_versions, mock_response_objects]

    version, objects = connector.get_knowledge_base_objects("cwe")

    assert version == "1.0"
    assert len(objects) == 2


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_get_knowledge_base_objects_empty(
    mock_session: MagicMock, connector: CTIButlerConnector
) -> None:
    """Test get_knowledge_base_objects with empty knowledge base"""
    connector.helper.get_state.return_value = {"versions": {}}

    mock_response = MagicMock()
    mock_response.json.return_value = {"versions": []}
    mock_response.raise_for_status = MagicMock()
    mock_session.get.return_value = mock_response

    with pytest.raises(KnowledgeBaseIsEmpty):
        connector.get_knowledge_base_objects("cwe")


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_get_knowledge_base_objects_already_ingested(
    mock_session: MagicMock, connector: CTIButlerConnector
) -> None:
    """Test get_knowledge_base_objects with already ingested version"""
    connector.helper.get_state.return_value = {"versions": {"cwe": ["1.0"]}}

    mock_response = MagicMock()
    mock_response.json.return_value = {"versions": ["1.0"]}
    mock_response.raise_for_status = MagicMock()
    mock_session.get.return_value = mock_response

    with pytest.raises(VersionAlreadyIngested):
        connector.get_knowledge_base_objects("cwe")


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_get_object_name() -> None:
    """Test get_object_name static method"""
    obj_with_ref = {
        "id": "weakness--1",
        "external_references": [{"external_id": "CWE-79"}],
    }
    name = CTIButlerConnector.get_object_name("cwe", obj_with_ref)
    assert name == "cwe => CWE-79"

    obj_without_ref = {"id": "weakness--1"}
    name = CTIButlerConnector.get_object_name("cwe", obj_without_ref)
    assert name == "cwe => weakness--1"


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_bundle_object_success(
    mock_session: MagicMock, connector: CTIButlerConnector
) -> None:
    """Test bundle_object success"""
    obj = {
        "id": "weakness--1",
        "external_references": [{"external_id": "CWE-79"}],
    }

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "total_results_count": 2,
        "objects": [{"type": "weakness", "id": "weakness--1"}],
    }
    mock_session.get.return_value = mock_response

    connector.helper.stix2_create_bundle.return_value = '{"type": "bundle"}'

    connector.bundle_object("cwe", obj, "test-work-id")

    connector.helper.send_stix2_bundle.assert_called_once()
    connector.helper.api.work.to_processed.assert_not_called()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_bundle_object_failure(
    mock_session: MagicMock, connector: CTIButlerConnector
) -> None:
    """Test bundle_object failure"""
    obj = {"id": "weakness--1", "external_references": [{"external_id": "CWE-79"}]}

    mock_session.get.side_effect = Exception("API Error")

    connector.bundle_object("cwe", obj, "test-work-id")

    connector.helper.api.work.report_expectation.assert_called_once()
    assert (
        connector.helper.api.work.report_expectation.call_args[1]["work_id"]
        == "test-work-id"
    )
    assert (
        "API Error"
        in connector.helper.api.work.report_expectation.call_args[1]["error"]["error"]
    )


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_run_once(mocker: MockerFixture, connector: CTIButlerConnector) -> None:
    """Test run_once method"""
    mocker.patch.object(
        connector,
        "get_knowledge_base_objects",
        return_value=("1.0", [{"id": "obj-1"}]),
    )
    mocker.patch.object(connector, "bundle_object")
    mocker.patch.object(connector, "update_state")

    connector.run_once()

    connector.helper.api.work.initiate_work.assert_called()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_run_in_work_success(connector: CTIButlerConnector) -> None:
    """Test _run_in_work context manager success"""
    with connector._run_in_work("Test Work") as work_id:
        assert work_id == "work-id"

    connector.helper.api.work.to_processed.assert_called_once_with(
        work_id="work-id", message="[CTIBUTLER] Work done", in_error=False
    )


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_run_in_work_failure(connector: CTIButlerConnector) -> None:
    """Test _run_in_work context manager failure"""
    with connector._run_in_work("Test Work"):
        raise ValueError("Test error")

    call_kwargs = connector.helper.api.work.to_processed.call_args[1]
    assert call_kwargs["in_error"] is True
    assert "[CTIBUTLER] Work failed" in call_kwargs["message"]
    assert "ValueError: Test error" in call_kwargs["message"]
