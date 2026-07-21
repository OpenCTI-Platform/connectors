"""Shared pytest fixtures for the VulnCheck connector tests.

Adds ``src`` to ``sys.path`` so tests import the ``connector`` and
``vulncheck_client`` packages, mocks the heavy ``OpenCTIConnectorHelper``
dependencies (so a real helper can be built without touching OpenCTI), and
exposes a ``StubConnectorSettings`` yielding a valid config without env/files.
"""

import os
import sys
from typing import Any
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from connector import ConnectorSettings  # noqa: E402


class StubConnectorSettings(ConnectorSettings):
    """ConnectorSettings with a fixed, valid config dict (no env/files needed)."""

    @classmethod
    def _load_config_dict(cls, _data: Any, handler: Any) -> dict[str, Any]:
        return handler(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "00000000-0000-0000-0000-000000000000",
                    "name": "VulnCheck",
                    "scope": "vulnerability,software",
                    "log_level": "info",
                    "duration_period": "PT1H",
                },
                "vulncheck": {"api_key": "test-api-key"},
            }
        )


@pytest.fixture
def settings() -> ConnectorSettings:
    return StubConnectorSettings()


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    """Mock heavy OpenCTIConnectorHelper dependencies (API calls, scheduler)."""
    module = "pycti.connector.opencti_connector_helper"
    for attr in (
        "killProgramHook",
        "ConnectorInfo",
        "OpenCTIApiClient",
        "OpenCTIConnector",
        "OpenCTIMetricHandler",
        "PingAlive",
    ):
        monkeypatch.setattr(f"{module}.{attr}", MagicMock(), raising=False)
    monkeypatch.setattr(f"{module}.sched.scheduler", MagicMock(), raising=False)


@pytest.fixture
def helper() -> MagicMock:
    """Lightweight mocked helper for unit tests that don't need a real one."""
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    helper.connect_id = "00000000-0000-0000-0000-000000000000"
    helper.connect_name = "VulnCheck"
    return helper
