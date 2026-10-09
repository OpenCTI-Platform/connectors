from typing import Any
from unittest.mock import MagicMock

import pytest
from pycti import OpenCTIConnectorHelper
from stream_connector import ZscalerConnector
from stream_connector.client import ZscalerClient
from stream_connector.settings import ConnectorSettings


class StubConnectorSettings(ConnectorSettings):
    """Subclass of ``ConnectorSettings`` returning a fake but valid config dict."""

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
                    "name": "Zscaler",
                    "scope": "domain-name",
                    "log_level": "info",
                    "live_stream_id": "live-stream-id",
                    "live_stream_listen_delete": True,
                    "live_stream_no_dependencies": True,
                },
                "zscaler": {
                    "client_id": "zscaler-client-id",
                    "client_secret": "zscaler-client-secret",
                    "vanity_domain": "acme",
                    "blacklist_name": "BLACK_LIST_DYNDNS",
                    "ssl_verify": False,
                },
            }
        )


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    """Mock all heavy dependencies of OpenCTIConnectorHelper (API calls to OpenCTI)."""

    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())


def test_connector_settings_is_instantiated():
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.connect_id == "connector-id"
    assert helper.connect_live_stream_id == "live-stream-id"


def test_connector_is_instantiated(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    client = ZscalerClient(
        logger=helper.connector_logger,
        client_id=settings.zscaler.client_id,
        client_secret=settings.zscaler.client_secret.get_secret_value(),
        vanity_domain=settings.zscaler.vanity_domain,
        cloud=settings.zscaler.cloud,
        ssl_verify=settings.zscaler.ssl_verify,
    )
    connector = ZscalerConnector(
        helper=helper,
        client=client,
        zscaler_blacklist_name=settings.zscaler.blacklist_name,
    )

    assert connector.helper is helper
    assert connector.client is client
    assert connector.zscaler_blacklist_name == "BLACK_LIST_DYNDNS"
    assert client.base_url == "https://api.zsapi.net/zia/api/v1"
    assert client.token_url == "https://acme.zslogin.net/oauth2/v1/token"
    assert client.ssl_verify is False
