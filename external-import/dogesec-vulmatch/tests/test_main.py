from copy import deepcopy
from datetime import timedelta
from typing import Any
from unittest.mock import MagicMock
from urllib.parse import urljoin

import pytest
from connector import VulmatchConnector
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
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
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
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "vulmatch",
                    "log_level": "error",
                    "duration_period": "P2D",
                },
                "vulmatch": {
                    "base_url": "https://api.vulmatch.com",
                    "api_key": "test-api-key",
                    "sbom_only": True,
                    "cvss_v2_score_min": -1,
                    "cvss_v3_score_min": 7,
                    "cvss_v4_score_min": 0,
                    "epss_score_min": 0.1,
                    "days_to_backfill": 500,
                },
            }
        )


def test_connector_settings_is_instantiated():
    """
    Test that the implementation of `BaseConnectorSettings` (from `connectors-sdk`) can be instantiated successfully:
        - the implemented class MUST have a method `to_helper_config` (inherited from `BaseConnectorSettings`)
        - the method `to_helper_config` MUST return a dict (as in base class)
    """
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """
    Test that `OpenCTIConnectorHelper` (from `pycti`) can be instantiated successfully:
        - the value of `settings.to_helper_config` MUST be the expected dict for `OpenCTIConnectorHelper`
        - the helper MUST be able to get its instance's attributes from the config dict

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "Test Connector"
    assert helper.connect_scope == "vulmatch"
    assert helper.log_level == "ERROR"


def test_connector_is_instantiated(
    monkeypatch, mock_opencti_connector_helper, mock_session
):
    """
    Test that the connector's main class builds its own settings and helper from them,
    and passes the custom values to the objects that use them.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_session: the Vulmatch HTTP session is mocked to avoid any external call
    """
    monkeypatch.setattr("connector.ConnectorSettings", StubConnectorSettings)

    connector = VulmatchConnector()

    assert isinstance(connector.config, StubConnectorSettings)
    assert isinstance(connector.helper, OpenCTIConnectorHelper)
    assert connector.helper.connect_id == "connector-id"
    assert connector.base_url == "https://api.vulmatch.com/"
    assert connector.api_key == "test-api-key"
    assert connector.sbom_only is True
    assert connector.cvss_v2_score_min is None
    assert connector.cvss_v3_score_min == 7
    assert connector.cvss_v4_score_min is None
    assert connector.epss_score_min == 0.1
    assert connector.days_to_backfill == 365
    assert connector.config.connector.duration_period == timedelta(days=2)
    assert connector.session is mock_session
    assert mock_session.headers == {"API-KEY": "test-api-key"}


def test_connector_run_uses_duration_period(
    monkeypatch, mock_opencti_connector_helper, mock_session
):
    """
    Test that the connector schedules its runs with `connector.duration_period`, in seconds.
    """
    monkeypatch.setattr("connector.ConnectorSettings", StubConnectorSettings)
    connector = VulmatchConnector()
    connector.helper = MagicMock()

    connector.run()

    connector.helper.schedule_process.assert_called_once_with(
        message_callback=connector.run_once, duration_period=2 * 86400
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
@pytest.mark.usefixtures("mock_opencti_connector_helper", "mock_session")
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
                config["vulmatch"]["base_url"] = base_url
                return handler(config)

            return super()._load_config_dict(_, with_base_url)

    monkeypatch.setattr("connector.ConnectorSettings", BaseUrlConnectorSettings)

    connector = VulmatchConnector()
    url = urljoin(connector.base_url, "v1/objects/")

    assert url == base_url.rstrip("/") + "/v1/objects/"
    assert "//" not in url.split("://", 1)[1]
