from typing import Any
from unittest.mock import MagicMock

import pytest
from main import RSTWhoisApiConnector
from pycti import OpenCTIConnectorHelper
from pycti.connector import opencti_connector_helper
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
                    "name": "RST WHOIS API",
                    "scope": "Domain-Name,Url,indicator",
                    "log_level": "info",
                    "auto": True,
                    "max_tlp": "TLP:AMBER",
                },
                "rst_whois_api": {
                    "api_key": "test-api-key",
                    "base_url": "https://api.rstcloud.net/v1/",
                    "timeout": 30,
                    "whois_output_object": "Description",
                    "update_output_action": "Append",
                    "output_format": "Extended",
                    "output_include_raw": True,
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
    assert helper.connect_name == "RST WHOIS API"
    assert helper.connect_scope == "Domain-Name,Url,indicator"
    assert helper.log_level == "INFO"
    assert helper.connect_auto is True


def test_connector_is_instantiated(mock_opencti_connector_helper, monkeypatch):
    """
    Test that the connector's main class builds its own settings and helper, and that
    the configured values reach the attributes used to call the RST WHOIS API.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    """
    monkeypatch.setattr("main.ConnectorSettings", StubConnectorSettings)

    connector = RSTWhoisApiConnector()

    assert isinstance(connector.config, StubConnectorSettings)
    assert isinstance(connector.helper, OpenCTIConnectorHelper)
    assert connector.helper.connect_id == connector.config.connector.id
    assert (
        opencti_connector_helper.OpenCTIConnector.call_args.kwargs[
            "playbook_compatible"
        ]
        is True
    )
    assert connector.base_url == "https://api.rstcloud.net/v1"
    assert connector.api_key == "test-api-key"
    assert connector.max_tlp == "amber"
    assert connector.timeout == 30
    assert connector.whois_output_object == "description"
    assert connector.update_output_action == "append"
    assert connector.output_format == "extended"
    assert connector.include_raw is True
    assert connector.connector_auto is True
