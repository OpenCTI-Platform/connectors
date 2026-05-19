import sys
from pathlib import Path
from typing import Annotated
from unittest.mock import patch

import pytest
from connectors_sdk.settings.base_settings import (
    BaseConfigModel,
    BaseConnectorSettings,
    _SettingsLoader,
)
from connectors_sdk.settings.deprecations import Deprecate, DeprecatedField
from connectors_sdk.settings.exceptions import ConfigValidationError
from pydantic import Field, HttpUrl


def test_base_config_model_should_retrieve_deprecated_fields():
    """Test that `BaseConfigModel` subclasses can retrieve deprecated fields metadata."""

    # Given: A BaseConfigModel subclass declaring one DeprecatedField
    class TestConfig(BaseConfigModel):
        test_field: str = Field(default="test")
        old_field: str = DeprecatedField(removal_date="2026-12-31")

    # When: The model is built
    # Then: The deprecated field is tracked in model's deprecated fields
    assert len(TestConfig.model_fields) == 2
    assert "old_field" in TestConfig.model_fields
    assert len(TestConfig._model_deprecated_fields) == 1
    assert "old_field" in TestConfig._model_deprecated_fields


def test_base_config_model_should_retrieve_fields_with_deprecate_annotation():
    """Test that `BaseConfigModel` subclasses can retrieve fields with `Deprecate` metadata."""

    # Given: A BaseConfigModel subclass with a field using Deprecate annotation
    class TestConfig(BaseConfigModel):
        test_field: str = Field(default="test")
        old_field: Annotated[
            str, Field(description="Test field"), Deprecate(removal_date="2026-12-31")
        ]

    # When: The model is built
    # Then: The annotated field is tracked in model's deprecated fields
    assert len(TestConfig.model_fields) == 2
    assert "old_field" in TestConfig.model_fields
    assert len(TestConfig._model_deprecated_fields) == 1
    assert "old_field" in TestConfig._model_deprecated_fields


def test_base_config_model_should_set_default_to_none_for_deprecated_fields():
    """Test that `BaseConfigModel` subclasses set `default` to `None` for deprecated fields."""

    # Given: A deprecated field explicitly defines a non-None default
    class TestConfig(BaseConfigModel):
        test_field: str = Field(default="test")
        old_field: str = DeprecatedField(
            default="deprecated default"  # should be overwritten to None
        )

    # When: The model field definitions are built
    # Then: Deprecated field defaults are normalized to None
    assert TestConfig.model_fields["old_field"].default is None
    assert TestConfig._model_deprecated_fields["old_field"].default is None


def test_base_config_model_should_disable_validate_default_for_deprecated_fields():
    """Test that `BaseConfigModel` subclasses set `validate_default` to `False` for deprecated fields."""

    # Given: A deprecated field that would normally validate its default
    class TestConfig(BaseConfigModel):
        test_field: str = Field(default="test")
        old_field: str = DeprecatedField(
            default="deprecated default"  # should be overwritten to None
        )

    # When: A model instance is created
    config = TestConfig()

    # Then: Deprecated defaults do not trigger validation and resolve to None
    assert config.old_field is None


def test_base_config_model_should_set_json_schema_extra_on_deprecated_fields():
    """Test that `BaseConfigModel` subclasses set `json_schema_extra` with deprecation info for deprecated fields."""

    # Given: A deprecated field with replacement metadata
    class TestConfig(BaseConfigModel):
        test_field: str = Field(default="test")
        old_field: str = DeprecatedField(
            new_namespaced_var="test_field",
            removal_date="2026-12-31",
        )

    # When: The model is built
    # Then: Deprecation information is exposed in field's json_schema_extra
    assert TestConfig.model_fields["old_field"].json_schema_extra == {
        "new_namespace": None,
        "new_namespaced_var": "test_field",
        "removal_date": "2026-12-31",
    }


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
            "log_level": "error",
            "scope": "test",
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
        "connector_log_level": "error",
        "connector_scope": "test",
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
    assert settings_dict["connector"]["scope"] == "test"
    assert settings_dict["connector"]["log_level"] == "error"


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
    assert settings_dict["connector"]["scope"] == "test"
    assert settings_dict["connector"]["log_level"] == "error"


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
    assert settings_dict["connector"]["scope"] == "test"
    assert settings_dict["connector"]["log_level"] == "error"


def test_base_connector_settings_should_validate_settings_from_config_yaml_file(
    mock_config_yml_file_presence,
):
    """
    Test that `BaseConnectorSettings` casts and validates config vars in `config.yml`.
    For testing purpose, the path of `config.yml` file is `tests/test_settings/data/config.test.yml`.
    """

    # Given: Valid connector settings are provided through config.yml fixture
    # When: BaseConnectorSettings is instantiated
    settings = BaseConnectorSettings()

    # Then: Values are validated and cast to expected runtime types
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

    # Given: Valid connector settings are provided through .env fixture
    # When: BaseConnectorSettings is instantiated
    settings = BaseConnectorSettings()

    # Then: Values are validated and cast to expected runtime types
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

    # Given: Valid connector settings are provided through patched os.environ
    # When: BaseConnectorSettings is instantiated
    settings = BaseConnectorSettings()

    # Then: Values are validated and cast to expected runtime types
    assert settings.opencti.url == HttpUrl("http://localhost:8080/")
    assert settings.opencti.token == "changeme"
    assert settings.connector.id == "connector-poc--uid"
    assert settings.connector.name == "Test Connector"
    assert settings.connector.scope == ["test"]
    assert settings.connector.log_level == "error"


def test_base_connector_settings_should_raise_when_missing_mandatory_env_vars():
    """Test that `BaseConnectorSettings` raises a `ValidationError` when no value is provided for required fields."""
    # Given: Mandatory connector settings are absent from env vars
    # When: BaseConnectorSettings is instantiated
    # Then: A ConfigValidationError is raised
    with pytest.raises(ConfigValidationError):
        BaseConnectorSettings()


def test_base_connector_settings_should_provide_helper_config(mock_environment):
    """
    Test that `BaseConnectorSettings().to_helper_config` returns a valid `config` dict for `pycti.OpenCTIConnectorHelper`.
    For testing purpose, `os.environ` is patched.
    """

    # Given: A valid BaseConnectorSettings instance built from patched environment
    # When: OpenCTIConnectorHelper config dict is generated
    settings = BaseConnectorSettings()
    opencti_dict = settings.to_helper_config()

    # Then: The resulting helper config dict matches expected structure and values
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


def test_base_connector_settings_model_json_schema_generates_the_default_json_schema():
    """Test that model_json_schema generates the default JSON schema."""

    # Given: BaseConnectorSettings uses default JSON schema generation
    # When: model_json_schema is called
    schema = BaseConnectorSettings.model_json_schema()

    # Then: The resulting schema contains top-level connector and opencti properties
    assert "$defs" in schema or "properties" in schema
    assert "opencti" in schema["properties"]
    assert "connector" in schema["properties"]


def test_base_connector_settings_config_json_schema():
    """Test config_json_schema generation."""
    # Given: A connector name for config JSON schema generation
    # When: config_json_schema is called
    schema = BaseConnectorSettings.config_json_schema(connector_name="test-connector")

    # Then: The config JSON schema contains standard schema metadata and properties
    assert "$schema" in schema
    assert "$id" in schema
    assert "test-connector" in schema["$id"]
    assert "properties" in schema

    # Then: Property names are uppercased
    assert "OPENCTI_URL" in schema["properties"]
    assert "OPENCTI_TOKEN" in schema["properties"]
    assert "CONNECTOR_NAME" in schema["properties"]

    # Then: CONNECTOR_ID is intentionally excluded from generated properties
    assert "CONNECTOR_ID" not in schema["properties"]
