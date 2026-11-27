from typing import Any
from unittest.mock import MagicMock

import pytest
import stix2
from main import Intel471AlertsConnector
from pycti import OpenCTIConnectorHelper
from settings import ConnectorSettings

API_URL = "https://intel471.test/v1"


class StubConnectorSettings(ConnectorSettings):
    """`ConnectorSettings` fed with a realistic dict instead of env vars or config files."""

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Intel 471 Darknet",
                    "scope": "intel471-darknet",
                    "log_level": "error",
                    "duration_period": "PT10M",
                },
                "intel471": {
                    # Trailing slash: the connector MUST strip it.
                    "api_url": f"{API_URL}/",
                    "api_username": "test-username",
                    "api_key": "test-api-key",
                },
                "intel471_darknet": {
                    "initial_history_alerts": 1700000000,
                    "tlp": "amber+strict",
                },
            }
        )


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    """Mock all heavy dependencies of OpenCTIConnectorHelper, typically API calls to OpenCTI."""

    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())


def _json_response(payload: dict) -> MagicMock:
    response = MagicMock()
    response.content = b"{}"
    response.json.return_value = payload
    return response


@pytest.fixture
def mock_intel471_api(monkeypatch) -> MagicMock:
    """Mock the Intel 471 watcher endpoints called by the connector constructor."""

    def fake_get(url, **_kwargs):
        if url.endswith("/watcherGroups"):
            return _json_response({"watcherGroups": [{"uid": "wg-1"}]})
        if url.endswith("/watcherGroups/wg-1/watchers"):
            return _json_response(
                {"watchers": [{"uid": "w-1", "description": "Ransomware leaks"}]}
            )
        return _json_response({})

    mock_get = MagicMock(side_effect=fake_get)
    monkeypatch.setattr("requests.get", mock_get)
    return mock_get


def test_connector_settings_is_instantiated():
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "Intel 471 Darknet"
    assert helper.connect_scope == "intel471-darknet"
    assert helper.log_level == "ERROR"


def test_connector_is_instantiated(
    mock_opencti_connector_helper, mock_intel471_api, monkeypatch
):
    monkeypatch.setattr("lib.external_import.ConnectorSettings", StubConnectorSettings)

    connector = Intel471AlertsConnector()

    assert isinstance(connector.config, StubConnectorSettings)
    assert isinstance(connector.helper, OpenCTIConnectorHelper)
    assert connector.helper.connect_id == "connector-id"
    assert connector._get_interval() == 600
    assert connector.intel471_api_url == API_URL
    assert connector.intel471_api_username == "test-username"
    assert connector.intel471_api_key == "test-api-key"
    assert connector.intel471_initial_history_alerts == 1700000000
    assert connector.intel471_darknet_marking["x_opencti_definition"] == (
        "TLP:AMBER+STRICT"
    )
    assert connector.intel471_darknet_tlp == [connector.intel471_darknet_marking.id]
    # The watchers are fetched from the configured API with the configured credentials.
    assert connector.intel471_watchers == {"w-1": "Ransomware leaks"}
    mock_intel471_api.assert_any_call(
        f"{API_URL}/watcherGroups",
        timeout=30,
        auth=("test-username", "test-api-key"),
    )


def test_connector_should_reject_a_zero_duration_period(
    mock_opencti_connector_helper, mock_intel471_api, monkeypatch
):
    class ZeroPeriodSettings(StubConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {"duration_period": "PT0S"},
                    "intel471": {"api_username": "user", "api_key": "key"},
                }
            )

    monkeypatch.setattr("lib.external_import.ConnectorSettings", ZeroPeriodSettings)

    with pytest.raises(ValueError, match="must be strictly positive"):
        Intel471AlertsConnector()


def test_connector_should_reject_an_unknown_tlp(
    mock_opencti_connector_helper, mock_intel471_api, monkeypatch
):
    class UnknownTlpSettings(StubConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "intel471": {"api_username": "user", "api_key": "key"},
                    "intel471_darknet": {"tlp": "purple"},
                }
            )

    monkeypatch.setattr("lib.external_import.ConnectorSettings", UnknownTlpSettings)

    with pytest.raises(ValueError, match="Unsupported INTEL471_DARKNET_TLP value"):
        Intel471AlertsConnector()


def test_run_cycle_should_send_the_bundle_without_update_flag(
    mock_opencti_connector_helper, mock_intel471_api, monkeypatch
):
    monkeypatch.setattr("lib.external_import.ConnectorSettings", StubConnectorSettings)
    connector = Intel471AlertsConnector()
    connector.helper = MagicMock()
    connector.helper.connect_name = "Intel 471 Darknet"
    connector.helper.api.work.initiate_work.return_value = "work-id"
    connector.helper.get_state.return_value = {}
    monkeypatch.setattr(
        connector, "_collect_intelligence", lambda since=None: [stix2.TLP_AMBER]
    )

    connector._run_cycle(last_run=None, timestamp=1700000000)

    connector.helper.send_stix2_bundle.assert_called_once()
    _, kwargs = connector.helper.send_stix2_bundle.call_args
    assert kwargs == {"work_id": "work-id"}
    connector.helper.set_state.assert_called_once_with({"last_run": 1700000000})
