"""Shared pytest fixtures for the whole test suite."""

import os
import sys
from typing import Any

import pytest

# Let test files import "connector"/"cyble_client" the same way `main.py` does.
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from connector import ConnectorSettings  # noqa: E402


class TestConnectorSettings(ConnectorSettings):
    """Valid `ConnectorSettings` that ignore the environment and `config.yml`."""

    @classmethod
    def _load_config_dict(cls, _: Any, handler: Any) -> dict[str, Any]:
        return handler(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "Incident",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "cyble_vision": {
                    "api_token": "test-api-token",
                },
            }
        )


@pytest.fixture
def connector_settings() -> TestConnectorSettings:
    """A fresh `TestConnectorSettings` for each test."""
    return TestConnectorSettings()
