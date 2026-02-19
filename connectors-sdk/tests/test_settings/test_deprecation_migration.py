"""Tests for deprecation migration in BaseConnectorSettings."""

import warnings

import pytest
from connectors_sdk.settings.base_settings import (
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from connectors_sdk.settings.deprecations import DeprecatedField
from connectors_sdk.settings.exceptions import ConfigValidationError
from pydantic import Field, SkipValidation


class TestMigrateDeprecation:
    """Test migrate_deprecation model validator."""

    def test_migrate_deprecated_variable_in_settings(self, monkeypatch):
        """Test variable migration during settings initialization."""

        class CustomConnectorConfig(BaseExternalImportConnectorConfig):
            old_field: str | None = DeprecatedField(
                deprecated="Use new_field instead",
                new_namespaced_var="new_field",
            )
            new_field: str = Field(default="default")

        class TestSettings(BaseConnectorSettings):
            connector: CustomConnectorConfig = Field(
                default_factory=CustomConnectorConfig
            )

        # Setup environment with deprecated variable
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.setenv("CONNECTOR_ID", "test-id")
        monkeypatch.setenv("CONNECTOR_NAME", "Test")
        monkeypatch.setenv("CONNECTOR_SCOPE", "test")
        monkeypatch.setenv("CONNECTOR_DURATION_PERIOD", "PT5M")
        monkeypatch.setenv("CONNECTOR_OLD_FIELD", "old_value")

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            settings = TestSettings()

            # Should have warnings about variable migration
            warning_messages = [str(warning.message) for warning in w]
            assert any("old_field" in msg.lower() for msg in warning_messages)

        # Should have migrated value
        assert settings.connector.new_field == "old_value"

    def test_migrate_deprecated_variable_with_value_transformation(self, monkeypatch):
        """Test variable migration with value transformation."""

        def double_value(val):
            return int(val) * 2

        class CustomConnectorConfig(BaseExternalImportConnectorConfig):
            old_value: str | None = DeprecatedField(
                deprecated="Use new_value instead",
                new_namespaced_var="new_value",
                new_value_factory=double_value,
            )
            new_value: int

        class TestSettings(BaseConnectorSettings):
            connector: CustomConnectorConfig = Field(
                default_factory=CustomConnectorConfig
            )

        # Setup environment
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.setenv("CONNECTOR_ID", "test-id")
        monkeypatch.setenv("CONNECTOR_NAME", "Test")
        monkeypatch.setenv("CONNECTOR_SCOPE", "test")
        monkeypatch.setenv("CONNECTOR_DURATION_PERIOD", "PT5M")
        monkeypatch.setenv("CONNECTOR_OLD_VALUE", "5")

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            settings = TestSettings()

        assert settings.connector.new_value == 10

    def test_migrate_deprecated_namespace_with_non_string_value(self, monkeypatch):
        """Test that namespace migration raises ValueError for non-string new_namespace."""

        class CustomConnectorConfig(BaseExternalImportConnectorConfig):
            pass

        class TestSettings(BaseConnectorSettings):
            connector: CustomConnectorConfig = Field(
                default_factory=CustomConnectorConfig,
                deprecated=True,
                json_schema_extra={"new_namespace": 123},  # Non-string value
            )

        # Setup environment
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.setenv("CONNECTOR_ID", "test-id")
        monkeypatch.setenv("CONNECTOR_NAME", "Test")
        monkeypatch.setenv("CONNECTOR_SCOPE", "test")
        monkeypatch.setenv("CONNECTOR_DURATION_PERIOD", "PT5M")

        # Should raise a ConfigValidationError due to non-string new_namespace
        with pytest.raises(
            ConfigValidationError, match="Error validating configuration"
        ):
            TestSettings()

    def test_error_when_namespace_has_new_namespaced_var_in_legacy_field(
        self, monkeypatch
    ):
        """Test that ValueError is raised when a deprecated namespace has new_namespaced_var."""

        class DeprecatedConfig(BaseExternalImportConnectorConfig):
            pass

        class TestSettings(BaseConnectorSettings):
            old_connector: DeprecatedConfig = Field(
                default_factory=DeprecatedConfig,
                deprecated="Use new_connector",
                json_schema_extra={
                    "new_namespace": "new_connector",
                    "new_namespaced_var": "renamed",  # This should trigger ValueError
                },
            )

        # Setup environment
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.setenv("OLD_CONNECTOR_ID", "test-id")
        monkeypatch.setenv("OLD_CONNECTOR_NAME", "Test")
        monkeypatch.setenv("OLD_CONNECTOR_SCOPE", "test")
        monkeypatch.setenv("OLD_CONNECTOR_DURATION_PERIOD", "PT5M")

        # This should raise during initialization wrapped in ConfigValidationError
        with pytest.raises(
            ConfigValidationError, match="Error validating configuration"
        ):
            TestSettings()

    def test_migrate_with_nested_field_metadata(self, monkeypatch):
        """Test migration with nested field-level new_namespace metadata."""

        class CustomConnectorConfig(BaseExternalImportConnectorConfig):
            special_field: str | None = DeprecatedField(
                deprecated="Moved to other_namespace",
                new_namespaced_var="renamed_field",
                new_namespace="other_namespace",
            )

        class TestSettings(BaseConnectorSettings):
            connector: CustomConnectorConfig = Field(
                default_factory=CustomConnectorConfig
            )
            other_namespace: dict = Field(default_factory=dict)

        # Setup environment
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.setenv("CONNECTOR_ID", "test-id")
        monkeypatch.setenv("CONNECTOR_NAME", "Test")
        monkeypatch.setenv("CONNECTOR_SCOPE", "test")
        monkeypatch.setenv("CONNECTOR_DURATION_PERIOD", "PT5M")
        monkeypatch.setenv("CONNECTOR_SPECIAL_FIELD", "special_value")

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            TestSettings()

            # Should have warnings about cross-namespace migration
            warning_messages = [str(warning.message) for warning in w]
            assert any("special_field" in msg.lower() for msg in warning_messages)

    def test_sub_field_migration_within_namespace(self, monkeypatch):
        """Test that sub-field migration works correctly within a namespace."""

        class CustomConnectorConfig(BaseExternalImportConnectorConfig):
            old_field: str | None = DeprecatedField(
                deprecated="Use new_field",
                new_namespaced_var="new_field",
            )
            new_field: str = Field(default="default_value")

        class TestSettings(BaseConnectorSettings):
            connector: CustomConnectorConfig = Field(
                default_factory=CustomConnectorConfig
            )

        # Setup environment
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.setenv("CONNECTOR_ID", "test-id")
        monkeypatch.setenv("CONNECTOR_NAME", "Test")
        monkeypatch.setenv("CONNECTOR_SCOPE", "test")
        monkeypatch.setenv("CONNECTOR_DURATION_PERIOD", "PT5M")
        monkeypatch.setenv("CONNECTOR_OLD_FIELD", "migrated_value")

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            settings = TestSettings()

            # Should have warnings about field migration
            warning_messages = [str(warning.message) for warning in w]
            assert any("old_field" in msg.lower() for msg in warning_messages)

            # Value should be migrated
            assert settings.connector.new_field == "migrated_value"

    def test_migrate_entire_namespace(self, monkeypatch):
        """Test that an entire namespace with all its fields is migrated."""

        class CustomConnectorConfig(BaseExternalImportConnectorConfig):
            custom_field: str = Field(default="default")
            api_key: str = Field(default="key")

        class TestSettings(BaseConnectorSettings):
            old_connector: SkipValidation[CustomConnectorConfig] = DeprecatedField(
                deprecated="Use connector namespace instead",
                new_namespace="connector",
            )
            connector: CustomConnectorConfig = Field(
                default_factory=CustomConnectorConfig
            )

        # Setup environment with only old_connector variables
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.setenv("OLD_CONNECTOR_ID", "old-id")
        monkeypatch.setenv("OLD_CONNECTOR_NAME", "Old Name")
        monkeypatch.setenv("OLD_CONNECTOR_SCOPE", "old-scope")
        monkeypatch.setenv("OLD_CONNECTOR_DURATION_PERIOD", "PT10M")
        monkeypatch.setenv("OLD_CONNECTOR_CUSTOM_FIELD", "migrated_custom")
        monkeypatch.setenv("OLD_CONNECTOR_API_KEY", "migrated_key")
        # Provide required but different fields for connector - old values should be used
        monkeypatch.setenv("CONNECTOR_ID", "new-id")
        monkeypatch.setenv("CONNECTOR_NAME", "New Name")
        monkeypatch.setenv("CONNECTOR_SCOPE", "new-scope")

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            settings = TestSettings()

            # Should have warnings about namespace migration
            warning_messages = [str(warning.message) for warning in w]
            assert any("old_connector" in msg.lower() for msg in warning_messages)

        # Fields from new namespace take precedence when both exist
        # (migration warns but doesn't override)
        assert settings.connector.id == "new-id"
        assert settings.connector.name == "New Name"
        assert settings.connector.scope == ["new-scope"]  # scope is a list
        # But fields that don't exist in new namespace are migrated
        assert settings.connector.custom_field == "migrated_custom"
        assert settings.connector.api_key == "migrated_key"
