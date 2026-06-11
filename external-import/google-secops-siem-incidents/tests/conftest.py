"""Shared fixtures and sys.path setup for google-secops connector tests."""

import os
import sys
from unittest.mock import MagicMock

import pytest

# Inject both src/ and tests/ so google_secops and test_helpers are importable.
_tests_dir = os.path.dirname(__file__)
sys.path.insert(0, _tests_dir)
sys.path.append(os.path.join(_tests_dir, "..", "src"))

from test_helpers import (  # noqa: E402
    FULL_VALID_CONFIG,
    MINIMAL_VALID_CONFIG,
    make_stub_settings,
)

__all__ = ["FULL_VALID_CONFIG", "MINIMAL_VALID_CONFIG", "make_stub_settings"]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    """Mock all heavy pycti internals so OpenCTIConnectorHelper can be created."""
    module_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_path}.PingAlive", MagicMock())


@pytest.fixture
def stub_settings():
    """Return a ConnectorSettings instance backed by the full valid config."""
    return make_stub_settings()()


@pytest.fixture(autouse=True)
def clear_rate_limiter_registry():
    """Clear the RateLimiterRegistry after each test to prevent inter-test leakage."""
    from google_secops_siem_incidents.utils.api_engine.rate_limiter import (
        RateLimiterRegistry,
    )

    yield
    RateLimiterRegistry.clear()
