import sys
from types import SimpleNamespace
import pytest


@pytest.fixture
def mock_main_path(monkeypatch):
    """Mock the path of `__main__.__file__` for `_SettingsLoader._get_connector_main_path` calls."""

    monkeypatch.setitem(
        sys.modules, "__main__", SimpleNamespace(__file__="/app/src/main.py")
    )

@pytest.fixture
def mock_basic_environment(monkeypatch):
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "changeme")
    monkeypatch.setenv("CONNECTOR_ID", "connector-poc--uid")
    monkeypatch.setenv("CONNECTOR_NAME", "Test Connector")
    monkeypatch.setenv("CONNECTOR_SCOPE", "test")
    monkeypatch.setenv("CONNECTOR_DURATION_PERIOD", "PT5M")
    monkeypatch.setenv("CONNECTOR_LOG_LEVEL", "error")


@pytest.fixture
def mock_yaml_file_presence(monkeypatch):
    def is_file(self):
        if self.name == "config.yml":
            return True
        return False

    monkeypatch.setattr("pathlib.Path.is_file", is_file)


@pytest.fixture
def mock_env_file_presence(monkeypatch):
    def is_file(self):
        if self.name == ".env":
            return True
        return False

    monkeypatch.setattr("pathlib.Path.is_file", is_file)


@pytest.fixture
def mock_yaml_config_settings_read_files(monkeypatch):
    def read_files(_, __):
        return {
            "connector": {
                "duration_period": "PT5M",
                "id": "connector-poc--uid",
                "log_level": "error",
                "name": "Test Connector",
                "scope": "test",
            },
            "opencti": {"token": "changeme", "url": "http://localhost:8080"},
        }

    monkeypatch.setattr(
        "pydantic_settings.YamlConfigSettingsSource._read_files", read_files
    )


@pytest.fixture
def mock_env_config_settings_read_env_files(monkeypatch):
    def _read_env_files(self):
        if self.settings_cls.__name__ == "SettingsLoader":
            return {
                "opencti": {"url": "http://localhost:8080", "token": "changeme"},
                "connector": {
                    "id": "connector-poc--uid",
                    "name": "Test Connector",
                    "duration_period": "PT5M",
                    "log_level": "error",
                    "scope": "test",
                },
            }
        return {}

    monkeypatch.setattr(
        "pydantic_settings.DotEnvSettingsSource._load_env_vars", _read_env_files
    )
