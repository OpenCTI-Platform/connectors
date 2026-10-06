from unittest.mock import MagicMock

import pytest
from pycti import OpenCTIConnectorHelper
from ransomwarelive.ransom_conn import RansomwareAPIConnector
from ransomwarelive.settings import ConnectorSettings


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    # Given
    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())


@pytest.fixture
def connector_env(monkeypatch):
    # Given
    env = {
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_TOKEN": "test-token",
        "CONNECTOR_ID": "connector-id",
        "CONNECTOR_NAME": "Test Connector",
        "CONNECTOR_SCOPE": "identity,report",
        "CONNECTOR_DURATION_PERIOD": "PT5M",
        "RANSOMWARELIVE_API_BASE_URL": "https://api.ransomware.live/v2",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return env


def test_connector_settings_is_instantiated(connector_env):
    # When
    settings = ConnectorSettings()

    # Then
    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(
    connector_env, mock_opencti_connector_helper
):
    # Given
    settings = ConnectorSettings()

    # When
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    # Then
    assert helper.opencti_url == "http://localhost:8080"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "Test Connector"
    assert helper.connect_scope == "identity,report"
    assert helper.connect_duration_period == "PT5M"


def test_connector_is_instantiated(connector_env, mock_opencti_connector_helper):
    # Given
    settings = ConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    # When
    connector = RansomwareAPIConnector(helper=helper, config=settings)

    # Then
    assert connector.config == settings
    assert connector.helper == helper
