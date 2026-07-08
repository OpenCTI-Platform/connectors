from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings, CybelAngel
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
    """
    Subclass of `ConnectorSettings` for testing purposes.
    Overrides `_load_config_dict` to return a fake but valid config dict.
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
                    "name": "CybelAngel",
                    "scope": "all",
                    "log_level": "error",
                    "duration_period": "PT6H",
                },
                "cybelangel": {
                    "client_id": "test-client-id",
                    "client_secret": "test-client-secret",
                    "api_url": "https://platform.cybelangel.com",
                    "auth_url": "https://auth.cybelangel.com/oauth/token",
                    "marking": "TLP:AMBER+STRICT",
                    "fetch_period": "7",
                },
            }
        )


def test_connector_settings_is_instantiated():
    """
    Test that `ConnectorSettings` can be instantiated successfully and that
    `to_helper_config` returns a dict.
    """
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """
    Test that `OpenCTIConnectorHelper` can be instantiated from `settings.to_helper_config()`.
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"


def test_connector_is_instantiated(mock_opencti_connector_helper):
    """
    Test that `CybelAngel` connector can be instantiated with config and helper.
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    connector = CybelAngel(config=settings, helper=helper)

    assert isinstance(connector, CybelAngel)
    assert connector.config == settings
    assert connector.helper == helper
