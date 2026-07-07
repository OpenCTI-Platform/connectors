from typing import Self
from unittest.mock import MagicMock

import pytest
from connector import ArcSightIncidentsConnector, ConnectorSettings
from pycti import OpenCTIConnectorHelper


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
    """Subclass of `ConnectorSettings` returning a fake but valid config dict."""

    @classmethod
    def _load_config_dict(cls, _, handler) -> Self:
        return handler(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "ArcSight Incidents",
                    "scope": "arcsight",
                    "log_level": "error",
                    "duration_period": "PT15M",
                },
                "arcsight_incidents": {
                    "api_base_url": "https://arcsight.example.com:8443",
                    "username": "api-user",
                    "password": "test-password",
                    "max_cases": 200,
                    "tlp_level": "amber",
                    "ssl_verify": True,
                },
            }
        )


def test_connector_settings_is_instantiated():
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_connector_is_instantiated(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    connector = ArcSightIncidentsConnector(config=settings, helper=helper)

    assert connector.config == settings
    assert connector.helper == helper
