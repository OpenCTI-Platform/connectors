from typing import Any
from unittest.mock import MagicMock

import pytest
from cloudflare_rules_list import Connector, ConnectorSettings
from cloudflare_rules_list.client import CloudflareRulesListClient
from pycti import OpenCTIConnectorHelper


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    """Mock all heavy dependencies of OpenCTIConnectorHelper (calls to OpenCTI)."""
    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())


class StubConnectorSettings(ConnectorSettings):
    """`ConnectorSettings` subclass returning a fixed, valid config dict."""

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "cloudflare",
                    "log_level": "error",
                    "live_stream_id": "live",
                    "live_stream_listen_delete": True,
                    "live_stream_no_dependencies": True,
                    "sync_interval": "1h",
                },
                "cloudflare": {
                    "account_id": "acc-1",
                    "api_token": "secret",
                    "list_id": "list-1",
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
    assert helper.connect_name == "Test Connector"
    assert helper.connect_scope == "cloudflare"
    assert helper.log_level == "ERROR"
    assert helper.connect_live_stream_id == "live"


def test_connector_is_instantiated(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    client = CloudflareRulesListClient(
        account_id=settings.cloudflare.account_id,
        api_token=settings.cloudflare.api_token.get_secret_value(),
    )
    connector = Connector(helper=helper, config=settings, client=client)

    assert connector.config == settings
    assert connector.helper == helper
    assert connector.list_id == "list-1"
    assert connector.sync_interval == 3600
