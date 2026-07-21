from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings, ProofpointEtIntelligenceConnector
from pycti import OpenCTIConnectorHelper


class StubConnectorSettings(ConnectorSettings):
    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token-for-testing",
                },
                "connector": {
                    "id": "f2de8084-47ab-4ff2-ae63-e5a7c6e5c720",
                    "name": "ProofPoint ET Intelligence",
                    "scope": "IPv4-Addr,Domain-Name,StixFile",
                    "auto": True,
                },
                "proofpoint_et_intelligence": {
                    "api_base_url": "https://api.emergingthreats.net/v1/",
                    "api_key": "test-api-key",
                    "max_tlp": "TLP:AMBER+STRICT",
                    "import_last_seen_time_window": "P30D",
                },
            }
        )


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())


def test_connector_settings_is_instantiated():
    settings = StubConnectorSettings()
    helper_config = settings.to_helper_config()
    assert isinstance(helper_config, dict)
    assert "opencti" in helper_config
    assert "connector" in helper_config


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(
        config=settings.to_helper_config(), playbook_compatible=True
    )
    assert helper.connect_id == "f2de8084-47ab-4ff2-ae63-e5a7c6e5c720"
    assert helper.connect_name == "ProofPoint ET Intelligence"


def test_connector_is_instantiated(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(
        config=settings.to_helper_config(), playbook_compatible=True
    )
    connector = ProofpointEtIntelligenceConnector(config=settings, helper=helper)
    assert connector.helper is helper
    assert (
        connector.config.proofpoint_et_intelligence.api_key.get_secret_value()
        == "test-api-key"
    )
    assert connector.config.proofpoint_et_intelligence.max_tlp == "TLP:AMBER+STRICT"
