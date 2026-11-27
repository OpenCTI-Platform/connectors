"""Pytest fixtures for ThreatFox connector tests."""

import os
import sys

import pytest

# The connector imports its modules as `src.*`, so its root must be importable.
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

MINIMAL_ENV = {
    "OPENCTI_URL": "http://localhost:8080",
    "OPENCTI_TOKEN": "test-token-00000000-0000-0000-0000-000000000000",
    "THREATFOX_AUTH_KEY": "test-auth-key",
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
