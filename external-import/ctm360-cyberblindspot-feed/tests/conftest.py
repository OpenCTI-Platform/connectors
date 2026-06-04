"""Common fixtures for ctm360-cyberblindspot-feed tests."""

import sys
from pathlib import Path

import pytest

# Add src directory to Python path so connector modules can be imported.
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


@pytest.fixture(autouse=True)
def _set_required_env_vars(monkeypatch):
    """Set the minimum environment variables required to instantiate ConnectorSettings."""
    # OpenCTI core settings
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv(
        "OPENCTI_TOKEN", "test-token-00000000-0000-0000-0000-000000000000"
    )

    # Connector core settings
    monkeypatch.setenv("CONNECTOR_ID", "00000000-0000-0000-0000-000000000000")
    monkeypatch.setenv("CONNECTOR_TYPE", "EXTERNAL_IMPORT")
    monkeypatch.setenv("CONNECTOR_NAME", "CTM360-CyberBlindSpot")
    monkeypatch.setenv("CONNECTOR_SCOPE", "ctm360-cbs")
    monkeypatch.setenv("CONNECTOR_DURATION_PERIOD", "PT24H")

    # Connector-specific required settings
    monkeypatch.setenv("CTM360_CBS_API_KEY", "test-api-key")
