from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import CyberThreatExchangeConnector
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
                    "name": "CyberThreatExchange",
                    "scope": "cyberthreatexchange",
                    "log_level": "error",
                    "duration_period": "PT12H",
                },
                "cyberthreatexchange": {
                    "base_url": "https://api.cyberthreatexchange.com/",
                    "api_key": "test-api-key",
                    "feed_ids": "feed-1,feed-2",
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
    assert helper.connect_name == "CyberThreatExchange"
    assert helper.connect_scope == "cyberthreatexchange"
    assert helper.log_level == "ERROR"


def test_connector_is_instantiated(mock_opencti_connector_helper, monkeypatch):
    """
    Test that the connector builds its settings and its helper from them,
    and that the custom settings reach the objects that use them.
    """
    monkeypatch.setattr("connector.ConnectorSettings", StubConnectorSettings)
    session = MagicMock()
    monkeypatch.setattr("connector.requests.Session", MagicMock(return_value=session))

    connector = CyberThreatExchangeConnector()

    assert isinstance(connector.config, StubConnectorSettings)
    assert isinstance(connector.helper, OpenCTIConnectorHelper)
    assert connector.helper.connect_id == "connector-id"
    assert connector.base_url == "https://api.cyberthreatexchange.com/"
    assert connector.api_key == "test-api-key"
    assert connector.feed_ids == ["feed-1", "feed-2"]
    assert connector.session is session
    assert session.headers == {"API-KEY": "test-api-key"}


def test_connector_should_exit_without_feed_ids(
    mock_opencti_connector_helper, monkeypatch
):
    """The connector MUST stop at startup when no feed ID is configured."""

    class NoFeedConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {},
                    "cyberthreatexchange": {"api_key": "test-api-key"},
                }
            )

    monkeypatch.setattr("connector.ConnectorSettings", NoFeedConnectorSettings)
    monkeypatch.setattr("connector.requests.Session", MagicMock())
    monkeypatch.setattr(OpenCTIConnectorHelper, "stop", MagicMock())

    with pytest.raises(SystemExit) as exc_info:
        CyberThreatExchangeConnector()
    assert exc_info.value.code == 1


def test_connector_schedules_with_duration_period(
    mock_opencti_connector_helper, monkeypatch
):
    """The connector MUST schedule its runs with `CONNECTOR_DURATION_PERIOD`, in seconds."""
    monkeypatch.setattr("connector.ConnectorSettings", StubConnectorSettings)
    monkeypatch.setattr("connector.requests.Session", MagicMock())

    connector = CyberThreatExchangeConnector()
    connector.helper.schedule_process = MagicMock()

    connector.run()

    connector.helper.schedule_process.assert_called_once_with(
        message_callback=connector.run_once, duration_period=12 * 3600
    )
