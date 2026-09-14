"""Pytest fixtures for ThreatFox connector tests."""

import os
import pytest
from unittest.mock import MagicMock, patch


MINIMAL_ENV = {
    "OPENCTI_URL": "http://localhost:8080",
    "OPENCTI_TOKEN": "test-token-00000000-0000-0000-0000-000000000000",
}


@pytest.fixture()
def minimal_env(monkeypatch):
    """Set the minimum required environment variables for the config loader."""
    for key, value in MINIMAL_ENV.items():
        monkeypatch.setenv(key, value)
    yield


@pytest.fixture(autouse=True)
def no_dotenv_or_yml(tmp_path, monkeypatch):
    """Prevent ConfigLoader from picking up .env or config.yml from the src dir."""
    # Point the config search to a temp dir where no .env or config.yml exists
    monkeypatch.chdir(tmp_path)
