from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings, DomainToolsIrisQLConnector
from pycti import OpenCTIConnectorHelper


class StubConnectorSettings(ConnectorSettings):
    """
    Subclass of `ConnectorSettings` for testing purpose.
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
                    "name": "DomainTools IrisQL",
                    "scope": "stix2",
                    "log_level": "error",
                    "duration_period": "PT1H",
                },
                "domaintools": {
                    "api_base_url": "https://api.domaintools.com/v1/iris-investigate/",
                    "api_key": "test-api-key",
                    "iris_ql": '# IrisQL-1.0\ndomain contains "sso"',
                    "store_iris_data": True,
                    "tlp_level": "clear",
                },
            }
        )


@pytest.fixture(name="mock_opencti_connector_helper")
def fixture_mock_opencti_connector_helper(monkeypatch):
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
    Test that the connector's settings is instantiated successfully
    (`to_helper_config()` is what makes the connector manager-supported).
    """
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """
    Test that the OpenCTI connector helper is instantiated successfully
    from the settings, and exposes the values of the connector config.
    """
    settings = StubConnectorSettings()

    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "DomainTools IrisQL"
    assert helper.connect_scope == "stix2"
    assert helper.log_level == "ERROR"


def test_connector_is_instantiated(mock_opencti_connector_helper):
    """
    Test that the connector is instantiated successfully
    with the settings and helper, and consumes the domaintools config.
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    connector = DomainToolsIrisQLConnector(config=settings, helper=helper)

    assert connector.config == settings
    assert connector.helper == helper
    assert connector.iris_ql == '# IrisQL-1.0\ndomain contains "sso"'
    assert connector.store_iris_data is True
    assert connector.client.session.headers["x-api-key"] == "test-api-key"
