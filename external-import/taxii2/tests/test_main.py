from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings
from connector.connector import Connector
from pycti import OpenCTIConnectorHelper

STUB_SETTINGS_DICT = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {
        "id": "connector-id",
        "name": "TAXII2",
        "scope": "ipv4-addr,ipv6-addr,vulnerability,domain,url,file-sha256,file-md5,file-sha1",
        "log_level": "error",
        "duration_period": "PT60M",
    },
    "taxii2": {
        "discovery_url": "https://taxii.example.com/taxii2/",
        "username": "test-username",
        "password": "test-password",
        "v21": True,
        "collections": "*.*",
        "initial_history": 24,
        "verify_ssl": True,
        "create_indicators": True,
        "create_observables": True,
        "author_name": "TAXII2 Author",
        "author_description": "TAXII2 Author description",
        "author_reliability": "A - Completely reliable",
    },
}


class StubConnectorSettings(ConnectorSettings):
    """
    Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
    It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
    """

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(STUB_SETTINGS_DICT)


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


@pytest.fixture
def stub_connector_settings(monkeypatch):
    """Force `Connector` to build its settings from `StubConnectorSettings`."""

    monkeypatch.setattr("connector.connector.ConnectorSettings", StubConnectorSettings)


def test_connector_settings_is_instantiated():
    """
    Test that the implementation of `BaseConnectorSettings` (from `connectors-sdk`) can be instantiated
    successfully:
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

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid
        any external calls to OpenCTI API
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "TAXII2"
    assert helper.connect_scope == (
        "ipv4-addr,ipv6-addr,vulnerability,domain,url,file-sha256,file-md5,file-sha1"
    )
    assert helper.log_level == "ERROR"
    assert helper.connect_duration_period == "PT1H"


def test_connector_is_instantiated(
    mock_opencti_connector_helper, stub_connector_settings
):
    """
    Test that the connector's main class can be instantiated successfully:
        - the connector's main class MUST be able to access env/config vars through `self.config`
        - the connector's main class MUST be able to access `pycti` API through `self.helper`

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid
        any external calls to OpenCTI API
    :param stub_connector_settings: `Connector` is fed by `StubConnectorSettings` during this test
        to avoid reading the real env/config vars
    """
    connector = Connector()

    assert isinstance(connector.config, ConnectorSettings)
    assert isinstance(connector.helper, OpenCTIConnectorHelper)
    assert connector.helper.connect_name == "TAXII2"
    assert connector.taxii2.config is connector.config
    assert connector.converter_to_stix.config is connector.config
    assert connector.process.config is connector.config
