from copy import deepcopy
from typing import Any
from unittest.mock import MagicMock
from urllib.parse import urljoin

import pytest
from obstracts import ObstractsConnector
from pycti import OpenCTIConnectorHelper
from settings import ConnectorSettings


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
                    "id": "connector-id",
                    "name": "Obstracts",
                    "scope": "obstracts",
                    "log_level": "error",
                    "duration_period": "PT12H",
                },
                "obstracts": {
                    "base_url": "https://api.obstracts.com",
                    "api_key": "test-api-key",
                    "feed_ids": "feed-1,feed-2",
                    "days_to_backfill": 90,
                },
            }
        )


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


def test_connector_settings_is_instantiated():
    """
    Test that the implementation of `BaseConnectorSettings` (from `connectors-sdk`) can be instantiated successfully.
    """
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """
    Test that `OpenCTIConnectorHelper` (from `pycti`) can be instantiated successfully
    with the connector settings converted by `to_helper_config()`.
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "Obstracts"
    assert helper.connect_scope == "obstracts"
    assert helper.log_level == "ERROR"


def test_connector_is_instantiated(mock_opencti_connector_helper, monkeypatch):
    """
    Test that the existing connector class builds its settings and its helper
    from `ConnectorSettings` and consumes the configured values.
    """
    monkeypatch.setattr("obstracts.ConnectorSettings", StubConnectorSettings)
    session = MagicMock()
    monkeypatch.setattr("obstracts.requests.Session", MagicMock(return_value=session))

    connector = ObstractsConnector()

    assert isinstance(connector.config, StubConnectorSettings)
    assert isinstance(connector.helper, OpenCTIConnectorHelper)
    assert connector.helper.connect_id == "connector-id"
    assert connector.base_url == "https://api.obstracts.com/"
    assert connector.api_key == "test-api-key"
    assert connector.feed_ids == ["feed-1", "feed-2"]
    assert connector.days_to_backfill == 90
    assert connector.session is session
    assert session.headers == {"API-KEY": "test-api-key"}


def test_connector_should_schedule_with_duration_period(
    mock_opencti_connector_helper, monkeypatch
):
    """The run loop MUST be scheduled every `CONNECTOR_DURATION_PERIOD` seconds."""
    monkeypatch.setattr("obstracts.ConnectorSettings", StubConnectorSettings)
    monkeypatch.setattr("obstracts.requests.Session", MagicMock())

    connector = ObstractsConnector()
    connector.helper.schedule_process = MagicMock()

    connector.run()

    connector.helper.schedule_process.assert_called_once_with(
        message_callback=connector.run_once,
        duration_period=12 * 3600,
    )


@pytest.mark.parametrize(
    "base_url",
    [
        "https://api.example.com",
        "https://api.example.com/",
        "https://api.example.com//",
        "http://proxy.local:8000/prefix",
        "http://proxy.local:8000/prefix/",
    ],
)
@pytest.mark.usefixtures("mock_opencti_connector_helper")
def test_connector_api_urls_have_no_double_slash(monkeypatch, base_url):
    """
    Test that the validated `base_url`, joined with an API path the way the
    connector does it, never produces a `//` in the URL path.
    """

    class BaseUrlConnectorSettings(StubConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            def with_base_url(config: dict[str, Any]) -> dict[str, Any]:
                config = deepcopy(config)
                config["obstracts"]["base_url"] = base_url
                return handler(config)

            return super()._load_config_dict(_, with_base_url)

    monkeypatch.setattr("obstracts.ConnectorSettings", BaseUrlConnectorSettings)
    monkeypatch.setattr("obstracts.requests.Session", MagicMock())

    connector = ObstractsConnector()
    url = urljoin(connector.base_url, "v1/objects/")

    assert url == base_url.rstrip("/") + "/v1/objects/"
    assert "//" not in url.split("://", 1)[1]
