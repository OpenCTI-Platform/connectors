# pragma: no cover  # do not test coverage of tests...
# isort: skip_file
# type: ignore
"""Provide unit tests for the connector wiring on the Pydantic settings."""

import os
import sys
from typing import Any
from unittest.mock import MagicMock

import pytest
from pycti import OpenCTIConnectorHelper

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from app import Connector
from tenable_security_center.settings import ConnectorSettings

STUB_SETTINGS_DICT = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {
        "id": "connector-id",
        "name": "Test Connector",
        "scope": "vulnerability",
        "log_level": "error",
        "duration_period": "PT12H",
    },
    "tsc": {
        "api_base_url": "https://tenable-security-center.test",
        "api_access_key": "test-access-key",
        "api_secret_key": "test-secret-key",
        "api_timeout": 30,
        "api_backoff": 5,
        "api_retries": 3,
        "export_since": "2024-11-18T12:00:00Z",
        "severity_min_level": "high",
        "process_systems_without_vulnerabilities": False,
        "marking_definition": "TLP:CLEAR",
        "number_threads": 1,
    },
}


class StubConnectorSettings(ConnectorSettings):
    """Subclass of `ConnectorSettings` for testing purpose.

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


def test_connector_settings_is_instantiated():
    """Test that `ConnectorSettings` can be instantiated successfully.

    - the implemented class MUST have a method `to_helper_config` (inherited from `BaseConnectorSettings`)
    - the method `to_helper_config` MUST return a dict (as in base class)
    """
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """Test that `OpenCTIConnectorHelper` (from `pycti`) can be instantiated successfully.

    - the value of `settings.to_helper_config` MUST be the expected dict for `OpenCTIConnectorHelper`
    - the helper MUST be able to get its instance's attributes from the config dict

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test
        to avoid any external calls to OpenCTI API
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "Test Connector"
    assert helper.connect_scope == "vulnerability"
    assert helper.connect_type == "EXTERNAL_IMPORT"
    assert helper.log_level == "ERROR"
    assert helper.connect_duration_period == "PT12H"


def test_connector_is_instantiated(mock_opencti_connector_helper):
    """Test that the connector's main class can be instantiated successfully.

    - the connector's main class MUST be able to access env/config vars through `self.config`
    - the connector's main class MUST be able to access `pycti` API through `self.helper`

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test
        to avoid any external calls to OpenCTI API
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    connector = Connector(config=settings, assets=MagicMock(), helper=helper)

    assert connector.config == settings
    assert connector.helper == helper
    assert connector.config.tsc.api_base_url == "https://tenable-security-center.test"
    assert connector.config.tsc.api_access_key.get_secret_value() == "test-access-key"
    assert connector.config.tsc.api_secret_key.get_secret_value() == "test-secret-key"
    assert connector.config.tsc.number_threads == 1


def test_connector_settings_expose_stix_tlp_marking():
    """Test that the connector's marking definition is resolved into a STIX TLP marking."""
    settings = StubConnectorSettings()

    assert settings.tsc.marking_definition == "TLP:CLEAR"
    assert settings.tsc.tlp_marking.definition_type == "tlp"


def test_connector_settings_hide_secrets():
    """Test that the connector's secrets are not leaked by `to_helper_config`."""
    settings = StubConnectorSettings()

    helper_config = settings.to_helper_config()

    assert helper_config["tsc"]["api_access_key"] == "**********"
    assert helper_config["tsc"]["api_secret_key"] == "**********"
    # the OpenCTI token is the only secret expected in clear text by `pycti`
    assert helper_config["opencti"]["token"] == "test-token"
