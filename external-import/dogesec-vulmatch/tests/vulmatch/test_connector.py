from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, call

import freezegun
import pytest
from connector import VulmatchConnector, VulmatchException, parse_bool, parse_number
from pytest_mock import MockerFixture


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_connector_init(
    mocked_helper: MagicMock, mock_session: MagicMock, mock_config
) -> None:
    """Test connector initialization"""
    connector = VulmatchConnector()

    assert connector.base_url == "https://test-vulmatch-url/"
    assert connector.api_key == "test-api-key"
    assert connector.sbom_only is False
    assert connector.interval_days == 1
    assert connector.days_to_backfill == 7
    assert connector.session.headers == {"API-KEY": "test-api-key"}


@pytest.fixture
def connector(mocked_helper, mock_session: MagicMock, mock_config) -> VulmatchConnector:
    """Fixture for VulmatchConnector instance"""
    return VulmatchConnector()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_connector_run(connector: VulmatchConnector) -> None:
    """Test connector run method"""
    connector.run()

    assert connector.helper.log_info.call_count == 1
    connector.helper.log_info.assert_has_calls([call("Starting Vulmatch")])

    assert connector.helper.schedule_process.call_count == 1
    connector.helper.schedule_process.assert_called_once_with(
        message_callback=connector.run_once, duration_period=86400
    )


def test_parse_bool() -> None:
    """Test parse_bool helper function"""
    assert parse_bool("yes") is True
    assert parse_bool("true") is True
    assert parse_bool("1") is True
    assert parse_bool("Y") is True
    assert parse_bool("no") is False
    assert parse_bool("false") is False


def test_parse_number() -> None:
    """Test parse_number helper function"""
    assert parse_number(5) == 5
    assert parse_number(0) is None
    assert parse_number(-1) is None
    assert parse_number(None) is None


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_get_state_empty(connector: VulmatchConnector) -> None:
    """Test _get_state with empty state"""
    connector.helper.get_state.return_value = None

    state = connector._get_state()

    assert "last_vulnerability_modified" in state
    # Should be 7 days ago
    expected_date = (datetime.now(UTC) - timedelta(days=7)).isoformat()
    # Just check it's a valid ISO format date
    assert expected_date == state["last_vulnerability_modified"]


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_get_state_existing(connector: VulmatchConnector) -> None:
    """Test _get_state with existing state"""
    existing_state = {"last_vulnerability_modified": "2026-02-17T15:24:00Z"}
    connector.helper.get_state.return_value = existing_state

    state = connector._get_state()

    assert state == existing_state


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_update_state(connector: VulmatchConnector) -> None:
    """Test update_state method"""
    connector.helper.get_state.return_value = {
        "last_vulnerability_modified": "2026-02-17T15:24:00Z"
    }

    connector.update_state("2026-02-18T15:24:00Z")

    expected_call = connector.helper.set_state.call_args[0][0]
    assert expected_call["last_vulnerability_modified"] == "2026-02-18T15:24:00Z"
    assert "updated" in expected_call


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_list_cpes_in_sbom_not_sbom_only(connector: VulmatchConnector) -> None:
    """Test list_cpes_in_sbom when sbom_only is False"""
    connector.sbom_only = False

    cpes = connector.list_cpes_in_sbom()

    assert cpes == [""]


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_list_cpes_in_sbom_success(
    mock_session: MagicMock, connector: VulmatchConnector
) -> None:
    """Test list_cpes_in_sbom success"""
    connector.sbom_only = True

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "total_results_count": 2,
        "objects": [
            {"cpe": "cpe:2.3:a:vendor:product1"},
            {"cpe": "cpe:2.3:a:vendor:product2"},
        ],
    }
    mock_session.get.return_value = mock_response

    cpes = connector.list_cpes_in_sbom()

    assert len(cpes) == 2
    assert cpes[0] == "cpe:2.3:a:vendor:product1"


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_list_cpes_in_sbom_empty(
    mock_session: MagicMock, connector: VulmatchConnector
) -> None:
    """Test list_cpes_in_sbom with empty SBOM"""
    connector.sbom_only = True

    mock_response = MagicMock()
    mock_response.json.return_value = {"total_results_count": 0, "objects": []}
    mock_session.get.return_value = mock_response

    with pytest.raises(VulmatchException, match="failed to fetch CPEs from SBOM"):
        connector.list_cpes_in_sbom()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_retrieve(mock_session: MagicMock, connector: VulmatchConnector) -> None:
    """Test retrieve method with pagination"""
    # Mock two pages of results
    mock_response_1 = MagicMock()
    mock_response_1.json.return_value = {
        "total_results_count": 3,
        "objects": [{"id": "cve-1"}, {"id": "cve-2"}],
    }

    mock_response_2 = MagicMock()
    mock_response_2.json.return_value = {
        "total_results_count": 3,
        "objects": [{"id": "cve-3"}],
    }

    mock_session.get.side_effect = [mock_response_1, mock_response_2]

    objects = connector.retrieve("v1/test/", list_key="objects")

    assert len(objects) == 3
    assert objects[0]["id"] == "cve-1"
    assert objects[2]["id"] == "cve-3"
    assert mock_session.get.call_count == 2


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_get_vulnerabilities(
    mock_session: MagicMock, connector: VulmatchConnector
) -> None:
    """Test get_vulnerabilities method"""
    connector.helper.get_state.return_value = {
        "last_vulnerability_modified": "2026-02-17T15:24:00Z"
    }

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "total_results_count": 2,
        "objects": [
            {"name": "CVE-2024-0001", "modified": "2026-02-18T15:00:00Z"},
            {"name": "CVE-2024-0002", "modified": "2026-02-18T15:01:00Z"},
        ],
    }
    mock_session.get.return_value = mock_response

    vulns = connector.get_vulnerabilities(["cpe:2.3:a:vendor:product"])

    assert len(vulns) == 2


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_process_vulnerability_success(
    mock_session: MagicMock, connector: VulmatchConnector
) -> None:
    """Test process_vulnerability success"""
    vuln = {"name": "CVE-2024-0001", "modified": "2026-02-18T15:24:00Z"}

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "total_results_count": 2,
        "objects": [
            {"type": "vulnerability", "id": "vulnerability--1"},
            {"type": "indicator", "id": "indicator--1"},
        ],
    }
    mock_session.get.return_value = mock_response

    connector.helper.stix2_create_bundle.return_value = '{"type": "bundle"}'

    connector.process_vulnerability(vuln)

    connector.helper.send_stix2_bundle.assert_called_once()
    connector.helper.api.work.to_processed.assert_called_once()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_process_vulnerability_failure(
    mock_session: MagicMock, connector: VulmatchConnector
) -> None:
    """Test process_vulnerability failure"""
    vuln = {"name": "CVE-2024-0001", "modified": "2026-02-18T15:24:00Z"}

    mock_session.get.side_effect = Exception("API Error")

    connector.process_vulnerability(vuln)

    connector.helper.api.work.report_expectation.assert_called_once()
    call_kwargs = connector.helper.api.work.to_processed.call_args[1]
    assert call_kwargs["in_error"] is True


def test_transform_bundle_objects(connector: VulmatchConnector) -> None:
    """Test transform_bundle_objects method"""
    bundle_objects = [
        {
            "type": "vulnerability",
            "id": "vulnerability--1",
            "name": "CVE-2024-0001",
            "modified": "2026-02-18T15:24:00Z",
            "created": "2026-02-18T15:24:00Z",
            "object_marking_refs": ["marking--1"],
            "external_references": [
                {"source_name": "cve", "external_id": "CVE-2024-0001"}
            ],
        },
        {"type": "software", "id": "software--1", "name": "Product"},
        {"type": "grouping", "id": "grouping--1", "object_refs": ["software--1"]},
        {"type": "weakness", "id": "weakness--1"},  # Should be skipped
        {
            "type": "relationship",
            "id": "relationship--1",
            "source_ref": "indicator--1",
            "target_ref": "grouping--1",
            "relationship_type": "x-cpes-vulnerable",
        },
    ]

    transformed = connector.transform_bundle_objects(bundle_objects)

    # Check that weakness was removed
    types = [obj["type"] for obj in transformed]
    assert "weakness" not in types
    assert "grouping" not in types


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_run_once(mocker: MockerFixture, connector: VulmatchConnector) -> None:
    """Test run_once method"""
    mocker.patch.object(connector, "list_cpes_in_sbom", return_value=[""])
    mocker.patch.object(
        connector,
        "get_vulnerabilities",
        return_value=[{"name": "CVE-2024-0001", "modified": "2026-02-18T15:24:00Z"}],
    )
    mocker.patch.object(connector, "process_vulnerability")
    mocker.patch.object(connector, "update_state")

    connector.run_once()

    connector.helper.api.work.initiate_work.assert_called()


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_run_in_work_success(connector: VulmatchConnector) -> None:
    """Test _run_in_work context manager success"""
    with connector._run_in_work("Test Work") as work_id:
        assert work_id == "work-id"

    connector.helper.api.work.to_processed.assert_called_once_with(
        work_id="work-id", message="[VULMATCH] Work done", in_error=False
    )


@freezegun.freeze_time("2026-02-18T15:24:00Z")
def test_run_in_work_failure(connector: VulmatchConnector) -> None:
    """Test _run_in_work context manager failure"""
    with connector._run_in_work("Test Work"):
        raise ValueError("Test error")

    call_kwargs = connector.helper.api.work.to_processed.call_args[1]
    assert call_kwargs["in_error"] is True
    assert "[VULMATCH] Work failed" in call_kwargs["message"]
    assert "ValueError: Test error" in call_kwargs["message"]
