from typing import Any
from unittest.mock import MagicMock

import config
import pytest
from lib import external_import
from main import CustomConnector
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

    mock_connector = MagicMock()
    mock_connector.name = "Group-IB Test Connector"
    monkeypatch.setattr(
        f"{module_import_path}.OpenCTIConnector",
        MagicMock(return_value=mock_connector),
    )
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())


class StubConnectorSettings(ConnectorSettings):
    """
    Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
    It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
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
                    "id": "test-connector-id",
                    "name": "Group-IB Test Connector",
                    "scope": "stix2,ipv4-addr,ipv6-addr",
                    "log_level": "error",
                    "duration_period": "PT4H",
                    "update_existing_data": True,
                },
                "ti_api": {
                    "username": "user@example.com",
                    "token": "test-ti-token",
                    "url": "https://tap.group-ib.com/api/v2/",
                    "collections_apt_threat_enable": True,
                    "collections_apt_threat_ttl": 90,
                    "extra_settings_enable_statement_marking": False,
                },
            }
        )


def test_connector_settings_is_instantiated():
    """
    Test that the implementation of `BaseConnectorSettings` (from `connectors-sdk`)
    can be instantiated successfully.
    """
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """
    Test that `OpenCTIConnectorHelper` (from `pycti`) can be instantiated successfully
    from the config produced by the new Pydantic settings.
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "test-connector-id"
    assert helper.connect_name == "Group-IB Test Connector"
    assert helper.connect_scope == "stix2,ipv4-addr,ipv6-addr"
    assert helper.log_level == "ERROR"
    assert helper.connect_duration_period == "PT4H"


def test_connector_is_instantiated(monkeypatch, mock_opencti_connector_helper):
    """
    Test that the connector's main class (`CustomConnector`) can be instantiated
    successfully when its configuration flows through the new Pydantic settings.

    `config.ConnectorSettings` is patched with the stub so no real environment /
    `config.yml` is required, and the heavy `TIAdapter` dependency is mocked.
    """
    monkeypatch.setattr(config, "ConnectorSettings", StubConnectorSettings)
    monkeypatch.setattr(external_import, "TIAdapter", MagicMock())

    connector = CustomConnector()

    assert isinstance(connector.cfg, config.ConfigConnector)
    assert connector.helper is not None
    assert connector.interval == "PT4H"
    assert connector.update_existing_data is True
    # The helper must have been built from the settings' `to_helper_config()`.
    assert connector.cfg.to_helper_config()["opencti"]["token"] == "test-token"
