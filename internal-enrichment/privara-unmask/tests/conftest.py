import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))


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
def connector_env(monkeypatch):
    """A minimal valid configuration, from environment variables."""
    env = {
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_TOKEN": "00000000-0000-4000-8000-000000000000",
        "CONNECTOR_ID": "3f0c7a52-6a2e-4c43-9a51-8d7a1f0e5b21",
        "PRIVARA_UNMASK_API_KEY": "pvu_test1234_s3cr3tvalue-never-log-me",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return env
