from typing import Any
from unittest.mock import MagicMock

import pytest
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl
from requests.cookies import RequestsCookieJar
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


def test_connector_is_instantiated(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    connector = ZscalerConnector(
        helper=helper,
        ssl_verify=settings.zscaler.ssl_verify,
        zscaler_username=settings.zscaler.username,
        zscaler_password=settings.zscaler.password.get_secret_value(),
        zscaler_api_key=settings.zscaler.api_key.get_secret_value(),
        zscaler_api_base_url=settings.zscaler.api_base_url,
        zscaler_blacklist_name=settings.zscaler.blacklist_name,
    )

    assert connector.helper is helper
    assert connector.zscaler_username == "zscaler-user"
    assert connector.zscaler_blacklist_name == "BLACK_LIST_DYNDNS"
    assert connector.ssl_verify is False
    assert connector.zscaler_base_url == "https://zsapi.zscalertwo.net/api/v1"


@pytest.mark.parametrize(
    "api_base_url, expected_base_url",
    [
        pytest.param(
            HttpUrl("https://zsapi.zscalertwo.net/"),
            "https://zsapi.zscalertwo.net/api/v1",
            id="default_cloud",
        ),
        pytest.param(
            HttpUrl("https://zsapi.zscalerone.net"),
            "https://zsapi.zscalerone.net/api/v1",
            id="other_cloud_without_trailing_slash",
        ),
        pytest.param(
            HttpUrl("https://zsapi.zscloud.net/"),
            "https://zsapi.zscloud.net/api/v1",
            id="other_cloud_with_trailing_slash",
        ),
    ],
)
def test_connector_builds_base_url_from_api_base_url(api_base_url, expected_base_url):
    connector = ZscalerConnector(
        helper=MagicMock(),
        ssl_verify=False,
        zscaler_username="zscaler-user",
        zscaler_password="zscaler-password",
        zscaler_api_key="zscaler-api-key",
        zscaler_api_base_url=api_base_url,
        zscaler_blacklist_name="BLACK_LIST_DYNDNS",
    )

    assert connector.zscaler_base_url == expected_base_url


def test_authenticate_with_zscaler_uses_configured_api_base_url(connector):
    cookie_jar = RequestsCookieJar()
    cookie_jar.set("JSESSIONID", "session-id")
    response = MagicMock(status_code=200)
    connector.session.post = MagicMock(return_value=response)
    connector.session.cookies = cookie_jar

    connector.authenticate_with_zscaler()

    connector.session.post.assert_called_once()
    assert (
        connector.session.post.call_args.args[0]
        == "https://zsapi.example.com/api/v1/authenticatedSession"
    )
