import os
import sys
from typing import Any
from unittest.mock import MagicMock

import pytest
from pycti import OpenCTIConnectorHelper

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from connector import ConnectorSettings, MontysecurityC2TrackerConnector
from connectors_sdk.models import OrganizationAuthor, TLPMarking


@pytest.fixture
def mock_connector_settings():
    """Fixture StubConnectorSettings."""

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
                        "name": "Test Connector",
                        "scope": "test, connector",
                        "log_level": "error",
                        "duration_period": "PT5M",
                    },
                    "montysecurity_c2_tracker": {
                        "malware_list_url": "https://github.com/montysecurity/C2-Tracker/tree/main/data",
                        "malware_ips_base_url": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/",
                        "tlp_level": "clear",
                    },
                }
            )

    return StubConnectorSettings()


@pytest.fixture
def mock_connector_helper(monkeypatch, mock_connector_settings):
    """Fixture OpenCTIConnectorHelper"""
    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())

    return OpenCTIConnectorHelper(config=mock_connector_settings.to_helper_config())


@pytest.fixture
def mock_connector(mock_connector_settings, mock_connector_helper):
    """Fixture MontysecurityC2TrackerConnector"""
    montysecurity_connector = MontysecurityC2TrackerConnector(
        config=mock_connector_settings,
        helper=mock_connector_helper,
    )
    montysecurity_connector.client = MagicMock()
    montysecurity_connector.converter_to_stix.author = OrganizationAuthor(
        name="MontySecurity"
    )
    config_tlp_level = mock_connector_settings.montysecurity_c2_tracker.tlp_level
    montysecurity_connector.converter_to_stix.tlp_marking = TLPMarking(
        level=config_tlp_level.lower()
    )

    return montysecurity_connector
