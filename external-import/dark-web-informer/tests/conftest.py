import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture
def mock_env(monkeypatch):
    """Minimal environment required to instantiate ConnectorSettings."""
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
    monkeypatch.setenv("CONNECTOR_ID", "d1c5e2a7-0b3f-4e8a-9c6d-7f2b1a4e9c30")
    monkeypatch.setenv("DARK_WEB_INFORMER_API_KEY", "test-key")


@pytest.fixture
def settings(mock_env):
    from connector.settings import ConnectorSettings

    return ConnectorSettings()


@pytest.fixture
def helper():
    """Stand-in for OpenCTIConnectorHelper."""
    mock = MagicMock()
    mock.connect_id = "d1c5e2a7-0b3f-4e8a-9c6d-7f2b1a4e9c30"
    mock.api.work.initiate_work.return_value = "work-id"
    return mock
