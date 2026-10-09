from typing import Any
from unittest.mock import MagicMock

import pytest
from pycti import OpenCTIConnectorHelper
from splunk_connector import ConnectorSettings, SplunkConnector


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())


class StubConnectorSettings(ConnectorSettings):
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
                    "name": "Splunk Test",
                    "scope": "indicator,identity,incident",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "splunk": {
                    "base_url": "https://splunk.example.com:8089",
                    "token": "splunk-token",
                    "scopes": "indicator,identity,incident",
                },
            }
        )


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
    assert helper.connect_name == "Splunk Test"
    assert helper.connect_scope == "indicator,identity,incident"
    assert helper.log_level == "ERROR"


def test_connector_is_instantiated(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    connector = SplunkConnector(config=settings, helper=helper)

    assert connector.config == settings
    assert connector.helper == helper
    assert [importer.state_key for importer in connector.importers] == [
        "indicators",
        "identities",
        "incidents",
    ]
