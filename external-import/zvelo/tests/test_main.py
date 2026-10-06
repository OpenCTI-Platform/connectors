from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings, ConnectorZvelo
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
    """
    Subclass of ConnectorSettings for testing purpose.
    Overrides _load_config_dict to return a fake but valid config dict.
    """

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
                    "name": "Test Connector",
                    "scope": "ipv4-addr,ipv6-addr,domain,url,indicator,malware",
                    "log_level": "error",
                    "duration_period": "PT1H",
                },
                "zvelo": {
                    "client_id": "test-client-id",
                    "client_secret": "test-client-secret",
                    "collections": "phish,malicious,threat",
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
    assert helper.connect_scope == "ipv4-addr,ipv6-addr,domain,url,indicator,malware"
    assert helper.log_level == "ERROR"
    assert helper.connect_duration_period == "PT1H"


def test_connector_is_instantiated(mock_opencti_connector_helper):
    """Test that the connector's main class can be instantiated successfully."""
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    connector = ConnectorZvelo(config=settings, helper=helper)

    assert connector.config == settings
