import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from connectors_sdk.settings.base_settings import (
    BaseConfigModel,
    BaseConnectorSettings,
    _SettingsLoader,
)
from connectors_sdk.settings.deprecations import DeprecatedField
from pydantic import Field


def test_settings_loader_should_get_connector_main_path(mock_main_path):
    """
    Test that `_SettingsLoader._get_connector_main_path` locates connector's `main.py`.
    For testing purpose, a fake path is assigned to `sys.modules[__main__].__file__`.
    """

    # Given: The connector main module path is available
    # When: The main path resolver is executed
    main_path = _SettingsLoader._get_connector_main_path()

    # Then: The resolved main.py path matches the expected connector location
    assert main_path == Path("/app/src/main.py").resolve()


def test_settings_loader_should_raise_when_main_module_misses_file_attribute(
    mock_main_path,
):
    """
    Test that `_SettingsLoader._get_connector_main_path` raises a meaningful error in case `__main__.__file__` is missing.
    For testing purpose, `sys.modules[__main__].__file__` is set to `None`.
    """

    # Given: The __main__.__file__ attribute is missing
    sys.modules["__main__"].__file__ = None

    # When: The main path resolver is executed
    # Then: A runtime error is raised to signal invalid execution context
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

    # Given: Legacy config file (/src/config.yml) is present
    with patch("pathlib.Path.is_file", is_file):
        # When: The config.yml path resolver is executed
        config_yml_file_path = _SettingsLoader._get_config_yml_file_path()

    # Then: The legacy config.yml path is returned
    assert config_yml_file_path == Path("/app/src/config.yml").resolve()


def test_settings_loader_should_get_config_yml_file_path(mock_main_path):
    """
    Test that `_SettingsLoader._get_config_yml_file_path` locates connector's `config.yml` (new path).
    For testing purpose, a fake path is assigned to `sys.modules[__main__].__file__`.
    """

    def is_file(self: Path) -> bool:
        return self.name == "config.yml" and self.parent.name != "src"

    # Given: Root config file (/config.yml) is present
    with patch("pathlib.Path.is_file", is_file):
        # When: The config.yml path resolver is executed
        config_yml_file_path = _SettingsLoader._get_config_yml_file_path()

    # Then: The new config.yml path is returned
    assert config_yml_file_path == Path("/app/config.yml").resolve()


def test_settings_loader_should_get_dot_env_file_path(mock_main_path):
    """
    Test that `_SettingsLoader._get_dot_env_file_path` locates connector's `.env`.
    For testing purpose, a fake path is assigned to `sys.modules[__main__].__file__`.
    """

    def is_file(self: Path) -> bool:
        return self.name == ".env"

    # Given: Root env file (/.env) is present
    with patch("pathlib.Path.is_file", is_file):
        # When: The .env path resolver is executed
        dot_env_file_path = _SettingsLoader._get_dot_env_file_path()

    # Then: The .env file path is returned
    assert dot_env_file_path == Path("/app/.env").resolve()


def test_settings_loader_should_parse_config_yml_file(mock_config_yml_file_presence):
    """
    Test that `_SettingsLoader()` parses config vars in `config.yml`.
    For testing purpose, the path of `config.yml` file is `tests/test_settings/data/config.test.yml`.
    """
    # Given: A valid config.yml
    # When: The settings loader is instantiated and dumped
    settings_loader = _SettingsLoader()
    settings_dict = settings_loader.model_dump()

    # Then: Parsed nested settings match expected config.yml values
    assert settings_dict == {
        "opencti": {
            "url": "http://localhost:8080",
            "token": "changeme",
        },
        "connector": {
            "id": "connector-poc--uid",
            "name": "Test Connector",
            "duration_period": "PT5M",
            "log_level": "debug",
            "scope": "scope1,scope2",
        },
    }


def test_settings_loader_should_parse_dot_env_file(mock_dot_env_file_presence):
    """
    Test that `_SettingsLoader()` parses env vars in `.env`.
    For testing purpose, the path of `.env` file is `tests/test_settings/data/.env.test`.
    """

    # Given: A valid .env file
    # When: The settings loader is instantiated and dumped
    settings_loader = _SettingsLoader()
    settings_dict = settings_loader.model_dump()

    # Then: Parsed flat settings match expected environment variables
    assert settings_dict == {
        "opencti_url": "http://localhost:8080",
        "opencti_token": "changeme",
        "connector_id": "connector-poc--uid",
        "connector_name": "Test Connector",
        "connector_duration_period": "PT5M",
        "connector_log_level": "debug",
        "connector_scope": "scope1,scope2",
    }


def test_settings_loader_should_not_parse_os_environ(mock_environment):
    """
    Test that `_SettingsLoader()` does not parse env vars from `os.environ` (for security purposes).
    For testing purpose, `os.environ` is patched.
    """

    # Given: Valid environment variables
    # When: The settings loader is instantiated and dumped
    settings_loader = _SettingsLoader()
    settings_dict = settings_loader.model_dump()

    # Then: No implicit values are parsed
    assert settings_dict == {}


def test_settings_loader_should_parse_config_yml_from_model(
    mock_config_yml_file_presence,
):
    """
    Test that `_SettingsLoader.build_loader_from_model` returns a `BaseSettings` subclass
    capable of parsing `config.yml` according to the given `BaseModel`.
    For testing purpose, the path of `config.yml` file is `tests/test_settings/data/config.test.yml`.
    """

    # Given: A model-aware loader is built for BaseConnectorSettings with config.yml fixture
    # When: The loader instance parses and dumps values
    settings_loader = _SettingsLoader.build_loader_from_model(BaseConnectorSettings)
    settings_dict = settings_loader().model_dump()

    # Then: Parsed nested settings expose expected OpenCTI and connector values
    assert settings_dict["opencti"]["url"] == "http://localhost:8080"
    assert settings_dict["opencti"]["token"] == "changeme"
    assert settings_dict["connector"]["id"] == "connector-poc--uid"
    assert settings_dict["connector"]["name"] == "Test Connector"
    assert settings_dict["connector"]["scope"] == "scope1,scope2"
    assert settings_dict["connector"]["log_level"] == "debug"


def test_settings_loader_should_parse_dot_env_from_model(mock_dot_env_file_presence):
    """
    Test that `_SettingsLoader.build_loader_from_model` returns a `BaseSettings` subclass
    capable of parsing `.env` according to the given `BaseModel`.
    For testing purpose, the path of `.env` file is `tests/test_settings/data/.env.test`.
    """

    # Given: A model-aware loader is built for BaseConnectorSettings with .env fixture
    # When: The loader instance parses and dumps values
    settings_loader = _SettingsLoader.build_loader_from_model(BaseConnectorSettings)
    settings_dict = settings_loader().model_dump()

    # Then: Parsed nested settings expose expected OpenCTI and connector values
    assert settings_dict["opencti"]["url"] == "http://localhost:8080"
    assert settings_dict["opencti"]["token"] == "changeme"
    assert settings_dict["connector"]["id"] == "connector-poc--uid"
    assert settings_dict["connector"]["name"] == "Test Connector"
    assert settings_dict["connector"]["scope"] == "scope1,scope2"
    assert settings_dict["connector"]["log_level"] == "debug"


def test_settings_loader_should_parse_os_environ_from_model(mock_environment):
    """
    Test that `_SettingsLoader.build_loader_from_model` returns a `BaseSettings` subclass
    capable of parsing `os.environ` according to the given `BaseModel`.
    For testing purpose, `os.environ` is patched.
    """

    # Given: A model-aware loader is built for BaseConnectorSettings with patched os.environ
    # When: The loader instance parses and dumps values
    settings_loader = _SettingsLoader.build_loader_from_model(BaseConnectorSettings)
    settings_dict = settings_loader().model_dump()

    # Then: Parsed nested settings expose expected OpenCTI and connector values
    assert settings_dict["opencti"]["url"] == "http://localhost:8080"
    assert settings_dict["opencti"]["token"] == "changeme"
    assert settings_dict["connector"]["id"] == "connector-poc--uid"
    assert settings_dict["connector"]["name"] == "Test Connector"
    assert settings_dict["connector"]["scope"] == "scope1,scope2"
    assert settings_dict["connector"]["log_level"] == "error"


def test_settings_loader_should_parse_os_environ_from_model_with_deprecated_fields(
    monkeypatch, mock_environment
):
    """
    Test that `_SettingsLoader.build_loader_from_model` returns a `BaseSettings` subclass
    capable of parsing `os.environ` according to the given `BaseModel` with deprecated fields.
    For testing purpose, `os.environ` is patched.
    """

    monkeypatch.setenv("DEPRECATED_NAMESPACE_TEST_FIELD", "deprecated_value")

    # Given: Connector settings model with deprecated fields
    class DeprecatedConfig(BaseConfigModel):
        test_field: str = Field(
            description="This is a test field.",
        )

    class DeprecatedConnectorSettings(BaseConnectorSettings):
        """A connector settings model with deprecated namespaces."""

        deprecated_namespace: DeprecatedConfig = DeprecatedField(
            deprecated="This namespace is deprecated.",
        )

    # When: The settings loader instance parses and dumps values
    settings_loader = _SettingsLoader.build_loader_from_model(
        DeprecatedConnectorSettings
    )
    settings_dict = settings_loader().model_dump()

    # Then: Parsed nested settings expose expected OpenCTI and connector values
    assert settings_dict["opencti"]["url"] == "http://localhost:8080"
    assert settings_dict["opencti"]["token"] == "changeme"
    assert settings_dict["connector"]["id"] == "connector-poc--uid"
    assert settings_dict["connector"]["name"] == "Test Connector"
    assert settings_dict["connector"]["scope"] == "scope1,scope2"
    assert settings_dict["connector"]["log_level"] == "error"
    assert settings_dict["deprecated_namespace"]["test_field"] == "deprecated_value"
