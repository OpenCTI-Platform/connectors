"""Shared pytest fixtures for the whole test suite."""

import os
import sys
from typing import Any
from unittest.mock import MagicMock

import pytest

# Let test files import "connector"/"template_client" the same way `main.py` does.
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from connector import ConnectorSettings  # noqa: E402

VALID_SETTINGS: dict[str, Any] = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {
        "id": "connector-id",
        "name": "Test Hunt",
        "scope": "opensearch",
        "log_level": "error",
        "security_platform_name": "Test SIEM",
    },
    "template": {
        "api_base_url": "https://siem.example.com/api/",
        "api_key": "test-api-key",
        "sigma_pipeline": "windows-logsources",
    },
}


class TestConnectorSettings(ConnectorSettings):
    """Fake but valid `ConnectorSettings` for tests (no env vars or config.yml)."""

    @classmethod
    def _load_config_dict(cls, _: Any, handler: Any) -> dict[str, Any]:
        return handler(VALID_SETTINGS)


@pytest.fixture
def connector_settings() -> TestConnectorSettings:
    """A fresh `TestConnectorSettings` for each test."""
    return TestConnectorSettings()


@pytest.fixture
def helper() -> MagicMock:
    """Mock pycti helper exposing the hunt API."""
    mock = MagicMock()
    mock.work_id = "work-1"
    mock.stix2_create_bundle.return_value = '{"type": "bundle"}'
    return mock
