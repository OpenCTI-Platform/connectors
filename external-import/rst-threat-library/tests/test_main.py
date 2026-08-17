from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings
from main import RSTThreatLibrary
from pycti import OpenCTIConnectorHelper
from pycti.connector import opencti_connector_helper as helper_mod


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    """Mock heavy dependencies of OpenCTIConnectorHelper (avoid OpenCTI calls)."""

    monkeypatch.setattr(helper_mod, "killProgramHook", MagicMock())
    monkeypatch.setattr(helper_mod.sched, "scheduler", MagicMock())
    monkeypatch.setattr(helper_mod, "ConnectorInfo", MagicMock())
    monkeypatch.setattr(helper_mod, "OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(helper_mod, "OpenCTIConnector", MagicMock())
    monkeypatch.setattr(helper_mod, "OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(helper_mod, "PingAlive", MagicMock())


class StubConnectorSettings(ConnectorSettings):
    """Stub ConnectorSettings with a valid in-memory config dict."""

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
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "rst_threat_library": {
                    "baseurl": "http://test.com",
                    "apikey": "test-api-key",
                    "auth_header": "x-api-key",
                },
            }
        )


def test_connector_settings_is_instantiated():
    settings = StubConnectorSettings()
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    assert helper.opencti_url is not None


def test_connector_is_instantiated(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    connector = RSTThreatLibrary(config=settings, helper=helper)
    assert connector.config == settings
    assert connector.helper == helper
