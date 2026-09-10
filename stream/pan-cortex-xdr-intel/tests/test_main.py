from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import Connector, ConnectorSettings
from cortex_xdr_client import CortexXdrClient
from pycti import OpenCTIConnectorHelper


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
                    "name": "Palo Alto Cortex XDR Intel",
                    "scope": "pan-cortex-xdr-intel",
                    "log_level": "error",
                    "live_stream_id": "test-stream-id",
                    "live_stream_listen_delete": True,
                    "live_stream_no_dependencies": True,
                },
                "pan_cortex_xdr_intel": {
                    "api_base_url": "https://api-test.com",
                    "api_key_id": "test-key-id",
                    "api_key": "test-api-key",
                },
            }
        )


def test_connector_settings_is_instantiated():
    """
    Test that the implementation of `BaseConnectorSettings` (from `connectors-sdk`) can be instantiated successfully:
        - the implemented class MUST have a method `to_helper_config` (inherited from `BaseConnectorSettings`)
        - the method `to_helper_config` MUST return a dict (as in base class)
    """
    # Given: A valid settings dict (stubbed via `StubConnectorSettings`)
    # When: We instantiate the settings
    settings = StubConnectorSettings()

    # Then: The settings instance is valid and can be converted to the helper config dict
    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """
    Test that `OpenCTIConnectorHelper` (from `pycti`) can be instantiated successfully:
        - the value of `settings.to_helper_config` MUST be the expected dict for `OpenCTIConnectorHelper`
        - the helper MUST be able to get its instance's attributes from the config dict

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    """
    # Given: Valid settings
    settings = StubConnectorSettings()

    # When: We instantiate the helper from the settings' helper config
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    # Then: The helper's attributes match the settings
    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "Palo Alto Cortex XDR Intel"
    assert helper.connect_scope == "pan-cortex-xdr-intel"
    assert helper.log_level == "ERROR"
    assert helper.connect_live_stream_id == "test-stream-id"
    assert helper.connect_live_stream_listen_delete == True
    assert helper.connect_live_stream_no_dependencies == True


def test_connector_is_instantiated(mock_opencti_connector_helper):
    """
    Test that the connector's main class can be instantiated successfully:
        - the connector's main class MUST be able to access env/config vars through `self.settings`
        - the connector's main class MUST be able to access `pycti` API through `self.helper`
        - the connector's main class MUST be able to access the Cortex XDR client through `self.client`

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    """
    # Given: Valid settings, a helper and a client
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    client = CortexXdrClient(
        api_base_url=settings.pan_cortex_xdr_intel.api_base_url,
        api_key_id=settings.pan_cortex_xdr_intel.api_key_id,
        api_key=settings.pan_cortex_xdr_intel.api_key.get_secret_value(),
    )

    # When: We instantiate the connector, injecting the helper, settings and client
    connector = Connector(helper=helper, settings=settings, client=client)

    # Then: The connector exposes the injected dependencies as-is
    assert connector.helper == helper
    assert connector.settings == settings
    assert connector.client == client
