"""Integration tests verifying the connector can be instantiated end-to-end."""

from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings, FlareConnector
from connector.converter_to_stix import FlareToStixMapper
from flare_client import FlareClient
from pycti import OpenCTIConnectorHelper


class StubConnectorSettings(ConnectorSettings):
    """ConnectorSettings subclass that loads config from a dict instead of env/file."""

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token-00000000-0000-0000-0000-000000000000",
                },
                "connector": {
                    "id": "aabbccdd-1234-5678-abcd-aabbccddeeff",
                    "name": "Flare",
                    "scope": "Incident,Observable,Indicator",
                    "duration_period": "PT1H",
                },
                "flare": {
                    "api_key": "fw_test_key_1234567890",
                    "api_base_url": "api.flare.io",
                    "event_types": "stealer_log,domain,ransomleak,leak",
                    "lookback_days": 30,
                    "tlp_level": "white",
                },
            }
        )


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    """Mock all external dependencies of OpenCTIConnectorHelper."""
    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())


def test_connector_settings_is_instantiated():
    """Verify ConnectorSettings can be instantiated and produces a valid helper config."""
    settings = StubConnectorSettings()
    config = settings.to_helper_config()
    assert isinstance(config, dict)
    assert config["opencti"]["url"] == "http://localhost:8080/"
    assert (
        config["opencti"]["token"] == "test-token-00000000-0000-0000-0000-000000000000"
    )
    assert config["connector"]["id"] == "aabbccdd-1234-5678-abcd-aabbccddeeff"
    assert config["connector"]["type"] == "EXTERNAL_IMPORT"


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """Verify OpenCTIConnectorHelper can be constructed from settings."""
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    assert helper.connect_id == "aabbccdd-1234-5678-abcd-aabbccddeeff"
    assert helper.connect_name == "Flare"


def test_connector_is_instantiated(mock_opencti_connector_helper):
    """Verify FlareConnector accepts config + helper + dependencies."""
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    flare_client = MagicMock(spec=FlareClient)
    mapper = MagicMock(spec=FlareToStixMapper)

    connector = FlareConnector(
        config=settings,
        helper=helper,
        flare_client=flare_client,
        mapper=mapper,
    )
    assert connector.config is settings
    assert connector.helper is helper
    assert connector.flare_client is flare_client
    assert connector.mapper is mapper
