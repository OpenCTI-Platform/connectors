from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings, ReversingLabsSpectraIntelConnector
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
    Subclass of `ConnectorSettings` for testing purpose.
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
                    "name": "Test Connector",
                    "scope": "Artifact,Url,StixFile,File",
                    "log_level": "error",
                },
                "reversinglabs_spectra_intel_submission": {
                    "url": "data.reversinglabs.com",
                    "username": "test-user",
                    "password": "test-password",
                    "max_tlp": "TLP:AMBER",
                    "sandbox_os": "windows10",
                    "sandbox_internet_sim": False,
                    "create_indicators": True,
                    "poll_interval": 250,
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
    helper = OpenCTIConnectorHelper(
        config=settings.to_helper_config(), playbook_compatible=True
    )

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "Test Connector"
    assert helper.connect_scope == "Artifact,Url,StixFile,File"
    assert helper.log_level == "ERROR"


def test_connector_is_instantiated(mock_opencti_connector_helper):
    """Test that the connector can be instantiated with config and helper."""
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(
        config=settings.to_helper_config(), playbook_compatible=True
    )

    connector = ReversingLabsSpectraIntelConnector(config=settings, helper=helper)

    assert connector.config == settings
    assert connector.helper == helper
