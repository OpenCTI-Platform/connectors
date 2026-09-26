# -*- coding: utf-8 -*-
"""Tests for the connector wiring.

They assert that `ConnectorSettings` can feed `pycti.OpenCTIConnectorHelper`
and that `XposedOrNotConnector` reads its behaviour from those settings,
mirroring the convention of the merged sibling connectors.
"""

from typing import Any
from unittest.mock import MagicMock

import pytest
from pycti import OpenCTIConnectorHelper
from src.xposedornot import ConnectorSettings, XposedOrNotConnector

VALID_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {
        "id": "connector-id",
        "name": "Test Connector",
        "scope": "Email-Addr",
        "log_level": "error",
        "auto": True,
    },
    "xposedornot": {
        "api_key": "test-api-key",
        "api_base_url": "https://api.xposedornot.com",
        "max_tlp": "TLP:AMBER+STRICT",
        "tlp_level": "amber+strict",
    },
}


class StubConnectorSettings(ConnectorSettings):
    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(VALID_SETTINGS_DICT)


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    """Mock the heavy dependencies of OpenCTIConnectorHelper, which would call OpenCTI."""
    path = "pycti.connector.opencti_connector_helper"
    for attribute in (
        "killProgramHook",
        "ConnectorInfo",
        "OpenCTIApiClient",
        "OpenCTIConnector",
        "OpenCTIMetricHandler",
        "PingAlive",
    ):
        monkeypatch.setattr(f"{path}.{attribute}", MagicMock())
    monkeypatch.setattr(f"{path}.sched.scheduler", MagicMock())


def test_connector_settings_is_instantiated():
    settings = StubConnectorSettings()
    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(
        config=settings.to_helper_config(), playbook_compatible=True
    )
    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "Test Connector"
    assert helper.connect_scope == "Email-Addr"
    assert helper.connect_type == "INTERNAL_ENRICHMENT"
    assert helper.log_level == "ERROR"
    assert helper.connect_auto is True


def test_connector_is_instantiated_from_settings(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(
        config=settings.to_helper_config(), playbook_compatible=True
    )
    connector = XposedOrNotConnector(config=settings, helper=helper)
    assert connector.config == settings
    assert connector.scopes == ["Email-Addr"]
    assert connector.max_tlp == "TLP:AMBER+STRICT"
    assert connector.tlp_level == "amber+strict"
    assert connector.client.api_key == "test-api-key"
    assert connector.client.base_url == "https://api.xposedornot.com"
