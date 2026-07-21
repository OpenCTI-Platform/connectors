from typing import Any
from unittest.mock import MagicMock

import pytest
import stix2
from connector import ConnectorSettings, MicrosoftDefenderIncidentsConnector
from connector.client_api import ConnectorClient
from connector.converter_to_stix import ConverterToStix


class StubConnectorSettings(ConnectorSettings):
    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "c4d8a1e2-3f5b-4c9d-8e7a-1b2c3d4e5f6a",
                    "name": "Microsoft Defender Incidents",
                    "scope": "defender",
                    "log_level": "error",
                    "duration_period": "PT1H",
                },
                "microsoft_defender_incidents": {
                    "tenant_id": "test-tenant-id",
                    "client_id": "test-client-id",
                    "client_secret": "test-client-secret",
                    "import_start_date": "2025-01-01T00:00:00Z",
                    "api_base_url": "https://graph.microsoft.com/v1.0",
                    "incident_path": "/security/incidents",
                },
            }
        )


@pytest.fixture
def stub_settings():
    return StubConnectorSettings()


@pytest.fixture
def mock_helper():
    h = MagicMock()
    h.connect_name = "Microsoft Defender Incidents"
    h.connect_id = "c4d8a1e2-3f5b-4c9d-8e7a-1b2c3d4e5f6a"
    return h


@pytest.fixture
def mock_config():
    config = MagicMock()
    mdi = MagicMock()
    mdi.tenant_id = "test-tenant"
    mdi.client_id = "test-client"
    mdi.client_secret.get_secret_value.return_value = "test-secret"
    mdi.api_base_url = "https://graph.microsoft.com/v1.0"
    mdi.incident_path = "/security/incidents"
    mdi.import_start_date = None
    config.microsoft_defender_incidents = mdi
    config.connector.duration_period = "PT1H"
    return config


@pytest.fixture
def converter(mock_helper, mock_config):
    return ConverterToStix(mock_helper, mock_config, stix2.TLP_RED)


@pytest.fixture
def client(mock_helper, mock_config):
    return ConnectorClient(mock_helper, mock_config)


@pytest.fixture
def connector_instance(mock_helper, mock_config):
    return MicrosoftDefenderIncidentsConnector(config=mock_config, helper=mock_helper)
