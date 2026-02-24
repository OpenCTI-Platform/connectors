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


def test_settings_loader_should_parse_config_yml_file(mock_config_yml_file_presence):
    """
    Test that `_SettingsLoader()` parses config vars in `config.yml`.
    For testing purpose, the path of `config.yml` file is `tests/test_settings/data/config.test.yml`.
    """
    settings_loader = _SettingsLoader()
    settings_dict = settings_loader.model_dump()

    assert settings_dict == {
        "opencti": {
            "url": "http://localhost:8080",
            "token": "changeme",
        },
        "connector": {
            "id": "connector-poc--uid",
            "name": "Test Connector",
            "duration_period": "PT5M",
            "log_level": "error",
            "scope": "test",
        },
    }


def test_settings_loader_should_parse_dot_env_file(mock_dot_env_file_presence):
    """
    Test that `_SettingsLoader()` parses env vars in `.env`.
    For testing purpose, the path of `.env` file is `tests/test_settings/data/.env.test`.
    """

    settings_loader = _SettingsLoader()
    settings_dict = settings_loader.model_dump()

    assert settings_dict == {
        "opencti_url": "http://localhost:8080",
        "opencti_token": "changeme",
        "connector_id": "connector-poc--uid",
        "connector_name": "Test Connector",
        "connector_duration_period": "PT5M",
        "connector_log_level": "error",
        "connector_scope": "test",
    }


def test_settings_loader_should_parse_os_environ(mock_environment):
    """
    Test that `_SettingsLoader()` parses env vars from `os.environ`.
    For testing purpose, `os.environ` is patched.
    """

    settings_loader = _SettingsLoader()
    settings_dict = settings_loader.model_dump()

    assert settings_dict == {}


def test_settings_loader_should_parse_config_yml_from_model(
    mock_config_yml_file_presence,
):
    """
    Test that `_SettingsLoader.build_loader_from_model` returns a `BaseSettings` subclass
    capable of parsing `config.yml` according to the given `BaseModel`.
    For testing purpose, the path of `config.yml` file is `tests/test_settings/data/config.test.yml`.
    """

    settings_loader = _SettingsLoader.build_loader_from_model(BaseConnectorSettings)
    settings_dict = settings_loader().model_dump()

    assert settings_dict["opencti"]["url"] == "http://localhost:8080"
    assert settings_dict["opencti"]["token"] == "changeme"
    assert settings_dict["connector"]["id"] == "connector-poc--uid"
    assert settings_dict["connector"]["name"] == "Test Connector"
    assert settings_dict["connector"]["scope"] == "test"
    assert settings_dict["connector"]["log_level"] == "error"


def test_settings_loader_should_parse_dot_env_from_model(mock_dot_env_file_presence):
    """
    Test that `_SettingsLoader.build_loader_from_model` returns a `BaseSettings` subclass
    capable of parsing `.env` according to the given `BaseModel`.
    For testing purpose, the path of `.env` file is `tests/test_settings/data/.env.test`.
    """

    settings_loader = _SettingsLoader.build_loader_from_model(BaseConnectorSettings)
    settings_dict = settings_loader().model_dump()

    assert settings_dict["opencti"]["url"] == "http://localhost:8080"
    assert settings_dict["opencti"]["token"] == "changeme"
    assert settings_dict["connector"]["id"] == "connector-poc--uid"
    assert settings_dict["connector"]["name"] == "Test Connector"
    assert settings_dict["connector"]["scope"] == "test"
    assert settings_dict["connector"]["log_level"] == "error"


def test_settings_loader_should_parse_os_environ_from_model(mock_environment):
    """
    Test that `_SettingsLoader.build_loader_from_model` returns a `BaseSettings` subclass
    capable of parsing `os.environ` according to the given `BaseModel`.
    For testing purpose, `os.environ` is patched.
    """

    settings_loader = _SettingsLoader.build_loader_from_model(BaseConnectorSettings)
    settings_dict = settings_loader().model_dump()

    assert settings_dict["opencti"]["url"] == "http://localhost:8080"
    assert settings_dict["opencti"]["token"] == "changeme"
    assert settings_dict["connector"]["id"] == "connector-poc--uid"
    assert settings_dict["connector"]["name"] == "Test Connector"
    assert settings_dict["connector"]["scope"] == "test"
    assert settings_dict["connector"]["log_level"] == "error"


def test_base_connector_settings_should_validate_settings_from_config_yaml_file(
    mock_config_yml_file_presence,
):
    """
    Test that `BaseConnectorSettings` casts and validates config vars in `config.yml`.
    For testing purpose, the path of `config.yml` file is `tests/test_settings/data/config.test.yml`.
    """

    settings = BaseConnectorSettings()

    assert settings.opencti.url == HttpUrl("http://localhost:8080/")
    assert settings.opencti.token == "changeme"
    assert settings.connector.id == "connector-poc--uid"
    assert settings.connector.name == "Test Connector"
    assert settings.connector.scope == ["test"]
    assert settings.connector.log_level == "error"


def test_base_connector_settings_should_validate_settings_from_dot_env_file(
    mock_dot_env_file_presence,
):
    """
    Test that `BaseConnectorSettings` casts and validates env vars in `.env`.
    For testing purpose, the path of `.env` file is `tests/test_settings/data/.env.test`.
    """

    settings = BaseConnectorSettings()

    assert settings.opencti.url == HttpUrl("http://localhost:8080/")
    assert settings.opencti.token == "changeme"
    assert settings.connector.id == "connector-poc--uid"
    assert settings.connector.name == "Test Connector"
    assert settings.connector.scope == ["test"]
    assert settings.connector.log_level == "error"


def test_base_connector_settings_should_validate_settings_from_os_environ(
    mock_environment,
):
    """
    Test that `BaseConnectorSettings` casts and validates env vars in `os.environ`.
    For testing purpose, `os.environ` is patched.
    """

    settings = BaseConnectorSettings()

    assert settings.opencti.url == HttpUrl("http://localhost:8080/")
    assert settings.opencti.token == "changeme"
    assert settings.connector.id == "connector-poc--uid"
    assert settings.connector.name == "Test Connector"
    assert settings.connector.scope == ["test"]
    assert settings.connector.log_level == "error"


def test_base_connector_settings_should_raise_when_missing_mandatory_env_vars():
    """Test that `BaseConnectorSettings` raises a `ValidationError` when no value is provided for required fields."""
    with pytest.raises(ConfigValidationError):
        BaseConnectorSettings()


def test_base_connector_settings_should_provide_helper_config(mock_environment):
    """
    Test that `BaseConnectorSettings().to_helper_config` returns a valid `config` dict for `pycti.OpenCTIConnectorHelper`.
    For testing purpose, `os.environ` is patched.
    """

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
        "opencti": {
            "token": "changeme",
            "url": "http://localhost:8080/",
        },
    }


def test_base_connector_settings_model_json_schema_uses_sanitizing_schema():
    """Test that model_json_schema uses SanitizingJsonSchema by default."""

    schema = BaseConnectorSettings.model_json_schema()

    # Should generate valid schema
    assert "$defs" in schema or "properties" in schema
    assert "opencti" in schema["properties"]
    assert "connector" in schema["properties"]


def test_base_connector_settings_flattened_json_schema():
    """Test flattened_json_schema generation."""
    schema = BaseConnectorSettings.config_json_schema(connector_name="test-connector")

    # Should have flattened structure
    assert "$schema" in schema
    assert "$id" in schema
    assert "test-connector" in schema["$id"]
    assert "properties" in schema

    # Should have uppercased environment variable names
    assert "OPENCTI_URL" in schema["properties"]
    assert "OPENCTI_TOKEN" in schema["properties"]
    assert "CONNECTOR_NAME" in schema["properties"]

    # CONNECTOR_ID should be filtered out
    assert "CONNECTOR_ID" not in schema["properties"]
