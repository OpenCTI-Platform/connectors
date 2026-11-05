from unittest.mock import MagicMock

import pytest
from conftest import make_settings
from connector import ConnectorSettings, DnslyticsConnector
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


def test_connector_settings_is_instantiated():
    settings = make_settings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    settings = make_settings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "DNSlytics"
    assert helper.connect_scope == "Indicator"
    assert helper.log_level == "ERROR"
    assert helper.connect_auto is False


def test_connector_is_instantiated(mock_opencti_connector_helper):
    settings = make_settings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    connector = DnslyticsConnector(config=settings, helper=helper)

    assert connector.config == settings
    assert connector.helper == helper


def test_main_module_imports_connector_settings():
    """XTM Composer imports `ConnectorSettings` from `src/main.py` to build the config schema."""
    import main

    assert main.ConnectorSettings is ConnectorSettings
