import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def mock_main_path(monkeypatch):
    """Mock the path of `__main__.__file__` for `_SettingsLoader._get_connector_main_path` calls."""

    monkeypatch.setitem(
        sys.modules, "__main__", SimpleNamespace(__file__="/app/src/main.py")
    )


@pytest.fixture
def mock_environment(monkeypatch):
    """Mock `os.environ` for `_SettingsLoader` and `BaseConnectorSettings` calls."""

    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "changeme")
    monkeypatch.setenv("CONNECTOR_ID", "connector-poc--uid")
    monkeypatch.setenv("CONNECTOR_NAME", "Test Connector")
    monkeypatch.setenv("CONNECTOR_SCOPE", "test")
    monkeypatch.setenv("CONNECTOR_DURATION_PERIOD", "PT5M")
    monkeypatch.setenv("CONNECTOR_LOG_LEVEL", "error")


@pytest.fixture
def mock_config_yml_file_presence(monkeypatch):
    """Mock the path of `config.yml` for `_SettingsLoader` and `BaseConnectorSettings` calls."""

    def get_config_yml_file_path():
        return Path(__file__).parent / "data" / "config.test.yml"

    monkeypatch.setattr(
        "connectors_sdk.settings.base_settings._SettingsLoader._get_config_yml_file_path",
        get_config_yml_file_path,
    )


@pytest.fixture
def mock_dot_env_file_presence(monkeypatch):
    """Mock the path of `.env` for `_SettingsLoader` and `BaseConnectorSettings` calls."""

    def get_dot_env_file_path():
        return Path(__file__).parent / "data" / ".env.test"

    monkeypatch.setattr(
        "connectors_sdk.settings.base_settings._SettingsLoader._get_dot_env_file_path",
        get_dot_env_file_path,
    )
