"""Canonical instantiation tests: settings -> helper -> connector.

Mirrors the external-import template's ``test_main.py``.
"""

from conftest import StubConnectorSettings
from pycti import OpenCTIConnectorHelper

from connector import ConnectorSettings
from connector.connector import ConnectorVulnCheck


def test_connector_settings_is_instantiated():
    settings = StubConnectorSettings()
    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url.rstrip("/") == "http://localhost:8080"
    assert helper.connect_id == "00000000-0000-0000-0000-000000000000"
    assert helper.connect_name == "VulnCheck"


def test_connector_is_instantiated(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    connector = ConnectorVulnCheck(config=settings, helper=helper)

    assert connector.config is settings
    assert connector.helper is helper
    assert type(connector.client).__name__ == "VulnCheckClient"
