import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from connectors_sdk.settings.base_settings import BaseConnectorSettings, _SettingsLoader
from connectors_sdk.settings.exceptions import ConfigValidationError
from pydantic import HttpUrl


def test_settings_loader_should_get_connector_main_path(mock_main_path):
    """
    Test that `_SettingsLoader._get_connector_main_path` locates connector's `main.py`.
    For testing purpose, a fake path is assigned to `sys.modules[__main__].__file__`.
    """

    main_path = _SettingsLoader._get_connector_main_path()

    assert main_path == Path("/app/src/main.py").resolve()


def test_settings_loader_should_raise_when_main_module_misses_file_attribute(
    mock_main_path,
):
    """
    Test that `_SettingsLoader._get_connector_main_path` raises a meaningful error in case `__main__.__file__` is missing.
    For testing purpose, `sys.modules[__main__].__file__` is set to `None`.
    """

    sys.modules["__main__"].__file__ = None

    with pytest.raises(RuntimeError):
        _SettingsLoader._get_connector_main_path()


def test_settings_loader_should_get_legacy_config_yml_file_path(
    mock_main_path,
):
    """
    Test that `_SettingsLoader._get_config_yml_file_path` locates connector's `config.yml` (legacy path).
    For testing purpose, a fake path is assigned to `sys.modules[__main__].__file__`.
    """

    def is_file(self: Path) -> bool:
        return self.name == "config.yml"

    with patch("pathlib.Path.is_file", is_file):
        config_yml_file_path = _SettingsLoader._get_config_yml_file_path()

    assert config_yml_file_path == Path("/app/src/config.yml").resolve()


def test_settings_loader_should_get_config_yml_file_path(mock_main_path):
    """
    Test that `_SettingsLoader._get_config_yml_file_path` locates connector's `config.yml` (new path).
    For testing purpose, a fake path is assigned to `sys.modules[__main__].__file__`.
    """

    def is_file(self: Path) -> bool:
        return self.name == "config.yml" and self.parent.name != "src"

    with patch("pathlib.Path.is_file", is_file):
        config_yml_file_path = _SettingsLoader._get_config_yml_file_path()

    assert config_yml_file_path == Path("/app/config.yml").resolve()


def test_settings_loader_should_get_dot_env_file_path(mock_main_path):
    """
    Test that `_SettingsLoader._get_dot_env_file_path` locates connector's `.env`.
    For testing purpose, a fake path is assigned to `sys.modules[__main__].__file__`.
    """

    def is_file(self: Path) -> bool:
        return self.name == ".env"

    with patch("pathlib.Path.is_file", is_file):
        dot_env_file_path = _SettingsLoader._get_dot_env_file_path()

    assert dot_env_file_path == Path("/app/.env").resolve()
    settings_loader = _SettingsLoader()
    settings_dict = settings_loader.model_dump()

    assert settings_dict == {}


def test_should_create_settings_loader_from_model(mock_basic_environment):
    settings_loader = _SettingsLoader.build_loader_from_model(BaseConnectorSettings)
    settings_dict = settings_loader().model_dump()

    assert settings_dict["opencti"]["url"] == "http://localhost:8080"
    assert settings_dict["opencti"]["token"] == "changeme"
    assert settings_dict["connector"]["id"] == "connector-poc--uid"
    assert settings_dict["connector"]["name"] == "Test Connector"
    assert settings_dict["connector"]["scope"] == "test"
    assert settings_dict["connector"]["log_level"] == "error"


def test_should_create_base_connector_settings(mock_basic_environment):
    settings = BaseConnectorSettings()
    assert settings.opencti.url == HttpUrl("http://localhost:8080/")
    assert settings.opencti.token == "changeme"
    assert settings.connector.id == "connector-poc--uid"
    assert settings.connector.name == "Test Connector"
    assert settings.connector.scope == ["test"]
    assert settings.connector.log_level == "error"


def test_should_fail_with_missing_mandatory_env_vars():
    with pytest.raises(ConfigValidationError):
        BaseConnectorSettings()


def test_should_dump_opencti_model(mock_basic_environment):
    settings = BaseConnectorSettings()
    opencti_dict = settings.to_helper_config()
    assert opencti_dict == {
        "connector": {
            "duration_period": "PT5M",
            "id": "connector-poc--uid",
            "log_level": "error",
            "name": "Test Connector",
            "scope": "test",
        },
        "opencti": {"token": "changeme", "url": "http://localhost:8080/"},
    }


def test_should_create_yml_settings_loader_from_model(
    mock_yaml_file_presence, mock_yaml_config_settings_read_files
):
    settings_loader = _SettingsLoader.build_loader_from_model(BaseConnectorSettings)
    settings_dict = settings_loader().model_dump()

    assert settings_dict["opencti"]["url"] == "http://localhost:8080"
    assert settings_dict["opencti"]["token"] == "changeme"
    assert settings_dict["connector"]["id"] == "connector-poc--uid"
    assert settings_dict["connector"]["name"] == "Test Connector"
    assert settings_dict["connector"]["scope"] == "test"
    assert settings_dict["connector"]["log_level"] == "error"


def test_should_load_settings_from_yaml_file(
    mock_yaml_file_presence, mock_yaml_config_settings_read_files
):
    settings = BaseConnectorSettings()
    assert settings.opencti.url == HttpUrl("http://localhost:8080/")
    assert settings.opencti.token == "changeme"
    assert settings.connector.id == "connector-poc--uid"
    assert settings.connector.name == "Test Connector"
    assert settings.connector.scope == ["test"]
    assert settings.connector.log_level == "error"


def test_should_create_dot_env_settings_loader_from_model(
    mock_env_file_presence, mock_env_config_settings_read_env_files
):
    settings_loader = _SettingsLoader.build_loader_from_model(BaseConnectorSettings)
    settings_dict = settings_loader().model_dump()

    assert settings_dict["opencti"]["url"] == "http://localhost:8080"
    assert settings_dict["opencti"]["token"] == "changeme"
    assert settings_dict["connector"]["id"] == "connector-poc--uid"
    assert settings_dict["connector"]["name"] == "Test Connector"
    assert settings_dict["connector"]["scope"] == "test"
    assert settings_dict["connector"]["log_level"] == "error"


def test_should_load_settings_from_env_file(
    mock_env_file_presence, mock_env_config_settings_read_env_files
):
    settings = BaseConnectorSettings()
    assert settings.opencti.url == HttpUrl("http://localhost:8080/")
    assert settings.opencti.token == "changeme"
    assert settings.connector.id == "connector-poc--uid"
    assert settings.connector.name == "Test Connector"
    assert settings.connector.scope == ["test"]
    assert settings.connector.log_level == "error"
