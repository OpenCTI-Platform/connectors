import pytest


@pytest.fixture
def mock_basic_environment(monkeypatch):
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "changeme")
    monkeypatch.setenv("CONNECTOR_ID", "CHANGEME")
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
                "log_level": "info",
                "name": "Connector POC",
                "scope": "ChangeMe",
            },
            "opencti": {"token": "token", "url": "http://localhost:8080"},
        }

    monkeypatch.setattr(
        "pydantic_settings.YamlConfigSettingsSource._read_files", read_files
    )


@pytest.fixture
def mock_env_config_settings_read_env_files(monkeypatch):
    def _read_env_files(self):
        if self.settings_cls.__name__ == "BaseConnectorSettings":
            return {
                "opencti": {"url": "http://localhost:8080", "token": "changeme"},
                "connector": {
                    "id": "CHANGEME",
                    "name": "Test Connector",
                    "duration_period": "PT5M",
                    "log_level": "error",
                    "scope": "test",
                },
            }
        return {}

    def _settings_build_values(_, *args, **kwargs):
        return {
            "opencti": {"url": "http://localhost:8080", "token": "changeme"},
            "connector": {
                "id": "CHANGEME",
                "name": "Test Connector",
                "scope": "test",
                "duration_period": "PT5M",
                "log_level": "error",
            },
        }

    monkeypatch.setattr(
        "pydantic_settings.DotEnvSettingsSource._load_env_vars", _read_env_files
    )
    # monkeypatch.setattr("pydantic_settings.BaseSettings._settings_build_values", _settings_build_values)
