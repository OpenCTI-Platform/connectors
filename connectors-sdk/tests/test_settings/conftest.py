from pathlib import Path

import pytest


@pytest.fixture
def mock_environment(monkeypatch):
    """Mock `os.environ` for `_SettingsLoader` and `BaseConnectorSettings` calls."""

    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "changeme")
    monkeypatch.setenv("CONNECTOR_ID", "connector-poc--uid")
    monkeypatch.setenv("CONNECTOR_NAME", "Test Connector")
    monkeypatch.setenv("CONNECTOR_SCOPE", "scope1,scope2")
    monkeypatch.setenv("CONNECTOR_DURATION_PERIOD", "PT5M")
    monkeypatch.setenv("CONNECTOR_LOG_LEVEL", "debug")


@pytest.fixture
def mock_config_yml_file_presence(monkeypatch):
    """Mock the path of `config.yml` for `_SettingsLoader` and `BaseConnectorSettings` calls."""

    def get_config_yml_file_path():
        return Path(__file__).parent.parent / "data" / "config.test.yml"

    monkeypatch.setattr(
        "connectors_sdk.settings.base_settings._SettingsLoader._get_config_yml_file_path",
        get_config_yml_file_path,
    )


@pytest.fixture
def mock_dot_env_file_presence(monkeypatch):
    """Mock the path of `.env` for `_SettingsLoader` and `BaseConnectorSettings` calls."""

    def get_dot_env_file_path():
        return Path(__file__).parent.parent / "data" / ".env.test"

    monkeypatch.setattr(
        "connectors_sdk.settings.base_settings._SettingsLoader._get_dot_env_file_path",
        get_dot_env_file_path,
    )
