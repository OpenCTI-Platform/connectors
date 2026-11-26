from typing import Any
from unittest.mock import MagicMock

import NameShield
import pytest
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
                    "name": "NAMESHIELD",
                    "scope": "NameShield",
                    "log_level": "error",
                    "duration_period": "P7D",
                },
                "nameshield": {
                    "auth_bearer": "test-bearer",
                    "server": "api.nameshield.net",
                    "api_version": "v1",
                    "api_endpoint": "registrar",
                    "url_list": "https://{server}/{api_endpoint}/{api_version}/domains",
                    "url_domain": "https://{server}/{api_endpoint}/{api_version}/domains/{domain}",
                    "domain_limit": 10000,
                    "marking": "TLP:GREEN",
                    "link_to_identities": "none",
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
    Test that the implementation of `BaseConnectorSettings` (from `connectors-sdk`) can be instantiated successfully:
        - the implemented class MUST have a method `to_helper_config` (inherited from `BaseConnectorSettings`)
        - the method `to_helper_config` MUST return a dict (as in base class)
    """
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """
    Test that `pycti.OpenCTIConnectorHelper` (from `pycti`) can be instantiated successfully:
        - the value of `settings.to_helper_config` MUST be the expected dict for `pycti.OpenCTIConnectorHelper`
        - the helper MUST be able to get its instance's attributes from the config dict

    :param mock_opencti_connector_helper: `pycti.OpenCTIConnectorHelper`'s dependencies are mocked
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "NAMESHIELD"
    assert helper.connect_scope == "NameShield"
    assert helper.log_level == "ERROR"


def test_connector_is_instantiated(mock_opencti_connector_helper, monkeypatch):
    """
    Test that the existing `NameShield` connector class can be instantiated with the settings:
        - the connector MUST build its own settings and the helper from them
        - every NameShield option MUST be read from the validated settings

    :param mock_opencti_connector_helper: `pycti.OpenCTIConnectorHelper`'s dependencies are mocked
    """
    monkeypatch.setattr(NameShield, "ConnectorSettings", StubConnectorSettings)

    connector = NameShield.NameShield()

    assert isinstance(connector.config, StubConnectorSettings)
    assert connector.helper.connect_id == "connector-id"
    assert connector.nameshield_auth_bearer == "test-bearer"
    assert connector.nameshield_server == "api.nameshield.net"
    assert connector.nameshield_api_version == "v1"
    assert connector.nameshield_api_endpoint == "registrar"
    assert connector.nameshield_interval == 7 * 24 * 60 * 60
    assert connector.nameshield_ioc_limit == 10000
    assert connector.nameshield_marking == "TLP:GREEN"
    assert connector.nameshield_link_to_identities == "none"
    assert (
        connector.make_url_dom_list()
        == "https://api.nameshield.net/registrar/v1/domains"
    )
    assert (
        connector.make_url_dom("example.com")
        == "https://api.nameshield.net/registrar/v1/domains/example.com"
    )
