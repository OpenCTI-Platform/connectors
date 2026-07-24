from typing import Annotated

import pytest
from connectors_sdk.logging.logger import Logger
from connectors_sdk.settings.base_settings import (
    BaseConfigModel,
    BaseConnectorSettings,
)
from connectors_sdk.settings.deprecations import Deprecate, DeprecatedField
from connectors_sdk.settings.exceptions import ConfigValidationError
from pydantic import Field, HttpUrl, SecretStr


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


def test_base_config_model_should_make_deprecated_fields_optional():
    """Test that `BaseConfigModel` subclasses set `default` to `None` for deprecated fields."""

    # Given: A deprecated field explicitly defined as required (non-optional)
    class TestConfig(BaseConfigModel):
        old_field: str = DeprecatedField()  # type should be overwritten to `str | None`

    # When: The model field definitions are built
    # Then: Deprecated field annotation is normalized to `str | None` to make it optional
    assert TestConfig.model_fields["old_field"].annotation == str | None
    assert TestConfig._model_deprecated_fields["old_field"].annotation == str | None


def test_base_config_model_should_set_default_to_none_for_deprecated_fields():
    """Test that `BaseConfigModel` subclasses set `default` to `None` for deprecated fields."""

    # Given: A deprecated field explicitly defines a non-None default
    class TestConfig(BaseConfigModel):
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


def test_base_connector_settings_init_subclass():
    class MySettings(BaseConnectorSettings):
        pass

    assert isinstance(MySettings.logger, Logger)
    assert MySettings.logger._logger.name.endswith(".MySettings")


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
    assert settings.opencti.token == SecretStr("changeme")
    assert settings.connector.id == "connector-poc--uid"
    assert settings.connector.name == "Test Connector"
    assert settings.connector.scope == ["scope1", "scope2"]
    assert settings.connector.log_level == "debug"


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
    assert settings.opencti.token == SecretStr("changeme")
    assert settings.connector.id == "connector-poc--uid"
    assert settings.connector.name == "Test Connector"
    assert settings.connector.scope == ["scope1", "scope2"]
    assert settings.connector.log_level == "debug"


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
    assert settings.opencti.token == SecretStr("changeme")
    assert settings.connector.id == "connector-poc--uid"
    assert settings.connector.name == "Test Connector"
    assert settings.connector.scope == ["scope1", "scope2"]
    assert settings.connector.log_level == "debug"


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
    json_dump = settings.model_dump(mode="json")
    opencti_dict = settings.to_helper_config()

    # Then: The regular JSON dump of settings does not expose the secret token value
    assert json_dump["opencti"]["token"] == "**********"
    assert json_dump["connector"]["scope"] == ["scope1", "scope2"]

    # Then: The resulting helper config dict matches expected structure and values
    assert opencti_dict == {
        "opencti": {
            "token": "changeme",  # clear token
            "url": "http://localhost:8080/",
        },
        "connector": {
            "duration_period": "PT5M",
            "id": "connector-poc--uid",
            "log_level": "debug",
            "name": "Test Connector",
            "scope": "scope1,scope2",  # comma-separated string
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
