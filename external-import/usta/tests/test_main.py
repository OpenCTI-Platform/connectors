"""Tests for the main entry point module."""

# pylint: disable=missing-function-docstring,too-few-public-methods

import os
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from connector import ConnectorSettings, ConverterToStix, UstaConnector
from pycti import OpenCTIConnectorHelper
from usta_client import UstaClient, UstaClientError

VALID_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {
        "id": "12345678-1234-1234-1234-123456789012",
        "name": "Test USTA",
        "scope": "indicator, report",
        "log_level": "error",
        "duration_period": "PT30M",
    },
    "usta": {
        "api_key": "test-api-key",
        "page_size": 50,
        "tlp_level": "amber",
        "confidence_level": 80,
    },
}


class StubConnectorSettings(ConnectorSettings):
    """
    Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
    It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
    """

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(VALID_SETTINGS_DICT)


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


def test_connector_imports():
    assert ConnectorSettings is not None
    assert ConverterToStix is not None
    assert UstaConnector is not None


def test_usta_client_imports():
    assert UstaClient is not None
    assert UstaClientError is not None


def test_connector_settings_is_instantiated():
    """
    Test that the implementation of `BaseConnectorSettings` (from `connectors-sdk`) can be
    instantiated successfully:
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
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "12345678-1234-1234-1234-123456789012"
    assert helper.connect_name == "Test USTA"
    assert helper.connect_scope == "indicator,report"
    assert helper.log_level == "ERROR"
    assert helper.connect_duration_period == "PT30M"


def test_connector_is_instantiated(mock_opencti_connector_helper):
    """
    Test that the connector's main class can be instantiated successfully:
        - the connector's main class MUST be able to access env/config vars through `self.config`
        - the connector's main class MUST be able to access `pycti` API through `self.helper`
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    connector = UstaConnector(config=settings, helper=helper)

    assert connector.config == settings
    assert connector.helper == helper
    assert connector.config.usta.page_size == 50
    assert connector.config.usta.api_key.get_secret_value() == "test-api-key"
    assert isinstance(connector.client, UstaClient)
    assert isinstance(connector.converter, ConverterToStix)


def test_usta_connector_init():
    env_vars = {
        "OPENCTI_URL": "https://opencti:8080",
        "OPENCTI_TOKEN": "fake-token",
        "CONNECTOR_ID": "12345678-1234-1234-1234-123456789012",
        "USTA_API_KEY": "test-key",
    }

    with patch.dict(os.environ, env_vars):
        settings = ConnectorSettings()

        # Mock OpenCTI helper to prevent AttributeError during dereferencing
        mock_helper = MagicMock()
        mock_helper.connector_logger = MagicMock()

        uc = UstaConnector(config=settings, helper=mock_helper)

        assert isinstance(uc.config, ConnectorSettings)
        assert isinstance(uc.client, UstaClient)
        assert isinstance(uc.converter, ConverterToStix)
        assert uc.helper == mock_helper
