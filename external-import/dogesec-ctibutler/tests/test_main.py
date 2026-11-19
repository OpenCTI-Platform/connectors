from datetime import timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import CTIButlerConnector
from pycti import OpenCTIConnectorHelper
from settings import ConnectorSettings


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


class StubConnectorSettings(ConnectorSettings):
    """`ConnectorSettings` returning a fixed, valid config dict instead of reading env vars or config.yml."""

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
                    "name": "CTIButler",
                    "scope": "ctibutler",
                    "log_level": "error",
                    "duration_period": "P1D",
                },
                "ctibutler": {
                    "base_url": "https://api.ctibutler.com",
                    "api_key": "test-api-key",
                    "knowledgebases": "attack-enterprise,capec",
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
    assert helper.connect_name == "CTIButler"
    assert helper.connect_scope == "ctibutler"
    assert helper.log_level == "ERROR"
    assert helper.connect_duration_period == "P1D"


def test_connector_is_instantiated(monkeypatch, mock_opencti_connector_helper):
    monkeypatch.setattr("connector.ConnectorSettings", StubConnectorSettings)
    session = MagicMock()
    monkeypatch.setattr("connector.requests.Session", MagicMock(return_value=session))

    connector = CTIButlerConnector()

    assert isinstance(connector.config, StubConnectorSettings)
    assert isinstance(connector.helper, OpenCTIConnectorHelper)
    assert connector.helper.connect_id == "connector-id"
    assert connector.base_url == "https://api.ctibutler.com/"
    assert connector.api_key == "test-api-key"
    assert connector.knowledgebases == ["attack-enterprise", "capec"]
    assert connector.session is session
    assert session.headers == {"API-KEY": "test-api-key"}
    assert connector.config.connector.duration_period == timedelta(days=1)


def test_connector_run_uses_duration_period(monkeypatch, mock_opencti_connector_helper):
    monkeypatch.setattr("connector.ConnectorSettings", StubConnectorSettings)
    monkeypatch.setattr("connector.requests.Session", MagicMock())
    connector = CTIButlerConnector()
    connector.helper.schedule_process = MagicMock()

    connector.run()

    connector.helper.schedule_process.assert_called_once_with(
        message_callback=connector.run_once, duration_period=86400
    )
