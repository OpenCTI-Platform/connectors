from typing import Any
from unittest.mock import MagicMock

import pytest
from pycti import OpenCTIConnectorHelper
from stream_connector import ZscalerConnector
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
                    "username": "zscaler-user",
                    "password": "zscaler-password",
                    "api_key": "zscaler-api-key",
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


def test_connector_is_instantiated(mock_opencti_connector_helper, monkeypatch):
    # ZscalerConnector builds an OpenCTIApiClient in __init__ - avoid real calls.
    monkeypatch.setattr("stream_connector.connector.OpenCTIApiClient", MagicMock())

    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    connector = ZscalerConnector(
        config_path=None,
        helper=helper,
        opencti_url=str(settings.opencti.url),
        opencti_token=settings.opencti.token,
        ssl_verify=settings.zscaler.ssl_verify,
        zscaler_username=settings.zscaler.username,
        zscaler_password=settings.zscaler.password.get_secret_value(),
        zscaler_api_key=settings.zscaler.api_key.get_secret_value(),
        zscaler_blacklist_name=settings.zscaler.blacklist_name,
    )

    assert connector.helper is helper
    assert connector.zscaler_username == "zscaler-user"
    assert connector.zscaler_blacklist_name == "BLACK_LIST_DYNDNS"
    assert connector.ssl_verify is False
