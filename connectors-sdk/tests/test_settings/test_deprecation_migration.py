"""Tests for deprecation migration in BaseConnectorSettings."""

import warnings

import pytest
from connectors_sdk.settings.base_settings import (
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from connectors_sdk.settings.deprecations import DeprecatedField
from connectors_sdk.settings.exceptions import ConfigValidationError
from pydantic import Field


class TestMigrateDeprecation:
    """Test migrate_deprecation model validator."""

    def test_migrate_deprecated_variable_in_settings(self, monkeypatch):
        """Test variable migration during settings initialization."""

        # Given: A settings model with a deprecated field mapped to a new field
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

        # When: TestSettings is instantiated
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            settings = TestSettings()

            # Then: A warning indicates the deprecated field migration
            warning_messages = [str(warning.message) for warning in w]
            assert any("old_field" in msg.lower() for msg in warning_messages)

        # And the deprecated value is copied into the replacement field
        assert settings.connector.new_field == "old_value"

    def test_migrate_deprecated_variable_with_non_string_value(self, monkeypatch):
        """Test that variable migration raises ValueError for non-string new_namespaced_var."""

        # Given: A deprecated field configured with wrongly typed argument
        class CustomConnectorConfig(BaseExternalImportConnectorConfig):
            old_field: str | None = DeprecatedField(
                deprecated="Use new_field instead",
                new_namespaced_var=123,  # type: ignore
            )
            new_field: str = Field(default="default")

        class TestSettings(BaseConnectorSettings):
            connector: CustomConnectorConfig = Field(
                default_factory=CustomConnectorConfig
            )

        # Setup mandatory environment variables only
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.setenv("CONNECTOR_ID", "test-id")
        monkeypatch.setenv("CONNECTOR_NAME", "Test")
        monkeypatch.setenv("CONNECTOR_SCOPE", "test")
        monkeypatch.setenv("CONNECTOR_DURATION_PERIOD", "PT5M")

        # When: Settings initialization evaluates migration metadata
        # Then: A ConfigValidationError is raised for invalid migration metadata
        with pytest.raises(
            ConfigValidationError, match="Error validating configuration"
        ):
            TestSettings()

    def test_migrate_deprecated_variable_with_value_transformation(self, monkeypatch):
        """Test variable migration with value transformation."""

        def double_value(val):
            return int(val) * 2

        # Given: A TestSettings model that migrates and transforms old_value into new_value
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

        # Setup environment variables with a deprecated value
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.setenv("CONNECTOR_ID", "test-id")
        monkeypatch.setenv("CONNECTOR_NAME", "Test")
        monkeypatch.setenv("CONNECTOR_SCOPE", "test")
        monkeypatch.setenv("CONNECTOR_DURATION_PERIOD", "PT5M")
        monkeypatch.setenv("CONNECTOR_OLD_VALUE", "5")

        # When: TestSettings is instantiated
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            settings = TestSettings()

        # Then: The migrated value is transformed by the factory
        assert settings.connector.new_value == 10

    def test_migrate_deprecated_namespace_with_non_string_value(self, monkeypatch):
        """Test that namespace migration raises ValueError for non-string new_namespace."""

        # Given: A deprecated namespace configured with wrongly typed argument
        class CustomConnectorConfig(BaseExternalImportConnectorConfig):
            pass

        class TestSettings(BaseConnectorSettings):
            connector: CustomConnectorConfig = DeprecatedField(
                default_factory=CustomConnectorConfig,
                deprecated=True,
                new_namespace=123,  # type: ignore
            )

        # Setup mandatory environment variables only
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.setenv("CONNECTOR_ID", "test-id")
        monkeypatch.setenv("CONNECTOR_NAME", "Test")
        monkeypatch.setenv("CONNECTOR_SCOPE", "test")
        monkeypatch.setenv("CONNECTOR_DURATION_PERIOD", "PT5M")

        # When: TestSettings initialization evaluates namespace migration metadata
        # Then: A ConfigValidationError is raised for invalid migration metadata
        with pytest.raises(
            ConfigValidationError, match="Error validating configuration"
        ):
            TestSettings()

    def test_error_when_namespace_has_new_namespaced_var_in_deprecated_field(
        self, monkeypatch
    ):
        """Test that ValueError is raised when a deprecated namespace has new_namespaced_var."""

        # Given: A deprecated namespace incorrectly defining new_namespaced_var
        class DeprecatedConfig(BaseExternalImportConnectorConfig):
            pass

        class TestSettings(BaseConnectorSettings):
            old_connector: DeprecatedConfig = DeprecatedField(
                default_factory=DeprecatedConfig,
                deprecated="Use new_connector",
                new_namespace="new_connector",
                new_namespaced_var="renamed",  # This should trigger ValueError
            )

        # Setup environment variables for the deprecated namespace
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.setenv("OLD_CONNECTOR_ID", "test-id")
        monkeypatch.setenv("OLD_CONNECTOR_NAME", "Test")
        monkeypatch.setenv("OLD_CONNECTOR_SCOPE", "test")
        monkeypatch.setenv("OLD_CONNECTOR_DURATION_PERIOD", "PT5M")

        # When: TestSettings initialization validates deprecated namespace migration
        # Then: A ConfigValidationError is raised for incompatible metadata combination
        with pytest.raises(
            ConfigValidationError, match="Error validating configuration"
        ):
            TestSettings()

    def test_migrate_with_nested_field_metadata(self, monkeypatch):
        """Test migration with nested field-level new_namespace metadata."""

        # Given: A deprecated field configured to migrate into another namespace
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

        # Setup environment variables with the deprecated field in connector namespace
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.setenv("CONNECTOR_ID", "test-id")
        monkeypatch.setenv("CONNECTOR_NAME", "Test")
        monkeypatch.setenv("CONNECTOR_SCOPE", "test")
        monkeypatch.setenv("CONNECTOR_DURATION_PERIOD", "PT5M")
        monkeypatch.setenv("CONNECTOR_SPECIAL_FIELD", "special_value")

        # When: TestSettings is instantiated
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            TestSettings()

            # Then: A warning indicates cross-namespace field migration
            warning_messages = [str(warning.message) for warning in w]
            assert any("special_field" in msg.lower() for msg in warning_messages)

    def test_sub_field_migration_within_namespace(self, monkeypatch):
        """Test that sub-field migration works correctly within a namespace."""

        # Given: A connector config with a deprecated field
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

        # Setup environment variables with only the deprecated field
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.setenv("CONNECTOR_ID", "test-id")
        monkeypatch.setenv("CONNECTOR_NAME", "Test")
        monkeypatch.setenv("CONNECTOR_SCOPE", "test")
        monkeypatch.setenv("CONNECTOR_DURATION_PERIOD", "PT5M")
        monkeypatch.setenv("CONNECTOR_OLD_FIELD", "migrated_value")

        # When: TestSettings is instantiated with warning capture enabled
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            settings = TestSettings()

            # Then: A warning indicates in-namespace field migration
            warning_messages = [str(warning.message) for warning in w]
            assert any("old_field" in msg.lower() for msg in warning_messages)

            # And the deprecated field value is assigned to the new field
            assert settings.connector.new_field == "migrated_value"

    def test_migrate_entire_namespace(self, monkeypatch):
        """Test that an entire namespace with all its fields is migrated."""

        # Given: A deprecated namespace configured to migrate into connector namespace
        class CustomConnectorConfig(BaseExternalImportConnectorConfig):
            custom_field: str = Field(default="default")
            api_key: str = Field(default="key")

        class TestSettings(BaseConnectorSettings):
            old_connector: CustomConnectorConfig = DeprecatedField(
                deprecated="Use connector namespace instead",
                new_namespace="connector",
            )
            connector: CustomConnectorConfig = Field(
                default_factory=CustomConnectorConfig
            )

        # Setup environment variables with both old namespace values and new namespace values
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.setenv("OLD_CONNECTOR_ID", "old-id")
        monkeypatch.setenv("OLD_CONNECTOR_NAME", "Old Name")
        monkeypatch.setenv("OLD_CONNECTOR_SCOPE", "old-scope")
        monkeypatch.setenv("OLD_CONNECTOR_DURATION_PERIOD", "PT10M")
        monkeypatch.setenv("OLD_CONNECTOR_CUSTOM_FIELD", "migrated_custom")
        monkeypatch.setenv("OLD_CONNECTOR_API_KEY", "migrated_key")
        monkeypatch.setenv("CONNECTOR_ID", "new-id")
        monkeypatch.setenv("CONNECTOR_NAME", "New Name")
        monkeypatch.setenv("CONNECTOR_SCOPE", "new-scope")

        # When: TestSettings is instantiated
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            settings = TestSettings()

            # Then: A warning indicates namespace-level migration
            warning_messages = [str(warning.message) for warning in w]
            assert any("old_connector" in msg.lower() for msg in warning_messages)

        # Then: Existing new-namespace values take precedence over migrated duplicates
        assert settings.connector.id == "new-id"
        assert settings.connector.name == "New Name"
        assert settings.connector.scope == ["new-scope"]  # scope is a list
        # Then: Missing new-namespace fields are filled from migrated old namespace values
        assert settings.connector.custom_field == "migrated_custom"
        assert settings.connector.api_key == "migrated_key"

    def test_migrate_both_namespace_and_field(self, monkeypatch):
        """Test that both namespace and field-level migration can occur together."""

        # Given: A config supporting both namespace-level and field-level deprecation migration
        class CustomConnectorConfig(BaseExternalImportConnectorConfig):
            new_field: str = Field(default="default")
            old_field: str | None = DeprecatedField(
                deprecated="Use new_field instead",
                new_namespace="connector",
                new_namespaced_var="new_field",
            )

        class TestSettings(BaseConnectorSettings):
            connector: CustomConnectorConfig = Field(
                default_factory=CustomConnectorConfig
            )
            old_connector: CustomConnectorConfig = DeprecatedField(
                deprecated="Use connector namespace instead",
                new_namespace="connector",
            )

        # Setup environment variables with only deprecated namespace and field values
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.setenv("OLD_CONNECTOR_ID", "old-id")
        monkeypatch.setenv("OLD_CONNECTOR_NAME", "Old Name")
        monkeypatch.setenv("OLD_CONNECTOR_SCOPE", "old-scope")
        monkeypatch.setenv("OLD_CONNECTOR_DURATION_PERIOD", "PT10M")
        monkeypatch.setenv("OLD_CONNECTOR_OLD_FIELD", "migrated_value")

        # When: TestSettings is instantiated
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            settings = TestSettings()

            # Then: Warnings indicate both namespace and field-level migrations
            warning_messages = [str(warning.message) for warning in w]
            assert any("old_connector" in msg.lower() for msg in warning_messages)
            assert any("old_field" in msg.lower() for msg in warning_messages)

        # And the deprecated field value is migrated to connector.new_field
        assert settings.connector.new_field == "migrated_value"
