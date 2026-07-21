from unittest.mock import MagicMock

import pytest
from connector import ComlaudeConnector, ConnectorSettings
from pycti import OpenCTIConnectorHelper


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    """Mock all heavy dependencies of OpenCTIConnectorHelper."""

    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())


class StubConnectorSettings(ConnectorSettings):
    """Subclass of ConnectorSettings for testing."""

    @classmethod
    def _load_config_dict(cls, _, handler) -> "StubConnectorSettings":
        return handler(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "comlaude, stix",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "comlaude": {
                    "username": "test-user",
                    "password": "test-password",
                    "api_key": "test-api-key",
                    "group_id": "test-group-id",
                    "score": 15,
                    "start_time": "1970-01-01T00:00:00Z",
                    "labels": "comlaude,safelist",
                },
            }
        )


def test_connector_settings_is_instantiated():
    """Test that ConnectorSettings can be instantiated successfully."""
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """Test that OpenCTIConnectorHelper can be instantiated from settings."""
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "Test Connector"
    assert helper.connect_scope == "comlaude,stix"
    assert helper.log_level == "ERROR"
    assert helper.connect_duration_period == "PT5M"


def test_connector_is_instantiated(mock_opencti_connector_helper):
    """Test that ComlaudeConnector can be instantiated successfully."""
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    connector = ComlaudeConnector(config=settings, helper=helper)

    assert connector.config == settings
    assert connector.helper == helper
