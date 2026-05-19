"""Tests for deprecation utilities."""

import warnings

import pytest
from connectors_sdk.settings.deprecations import (
    Deprecate,
    DeprecatedField,
    migrate_deprecated_namespace,
    migrate_deprecated_variable,
)
from pydantic.fields import FieldInfo


class TestMigrateDeprecatedNamespace:
    """Test migrate_deprecated_namespace function."""

    def test_migrate_with_empty_data(self):
        """Test migration with empty data dict."""
        # Given: An empty settings payload
        data: dict = {}

        # When: A deprecated namespace migration is requested
        migrate_deprecated_namespace(data, "old_ns", "new_ns")

        # Then: The payload remains unchanged
        assert data == {}

    def test_migrate_with_none_data(self):
        """Test migration with None data."""
        # Given: A missing settings payload
        data = None

        # When: A deprecated namespace migration is requested
        migrate_deprecated_namespace(data, "old_ns", "new_ns")  # type: ignore

        # Then: The payload remains None
        assert data is None

    def test_migrate_basic_namespace(self):
        """Test basic namespace migration."""
        # Given: Old namespace values and an empty target namespace
        data = {
            "old_namespace": {"key1": "value1", "key2": "value2"},
            "new_namespace": {},
        }

        # When: The old namespace is migrated to the new namespace
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            migrate_deprecated_namespace(data, "old_namespace", "new_namespace")

            # Then: A warning is emitted for each migrated key
            assert len(w) == 2
            assert "Deprecated setting 'old_namespace.key1'" in str(w[0].message)
            assert "Migrating to 'new_namespace.key1'" in str(w[0].message)
            assert "Deprecated setting 'old_namespace.key2'" in str(w[1].message)

        # Then: Old namespace is removed and values are present in the new namespace
        assert "old_namespace" not in data
        assert data["new_namespace"] == {"key1": "value1", "key2": "value2"}

    def test_migrate_with_existing_keys_in_new_namespace(self):
        """Test migration when keys already exist in new namespace."""
        # Given: Both old and new namespaces define the same key
        data = {
            "old_namespace": {"key1": "old_value"},
            "new_namespace": {"key1": "new_value"},
        }

        # When: Namespace migration is performed
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            migrate_deprecated_namespace(data, "old_namespace", "new_namespace")

            # Then: A warning indicates that the new namespace value is kept
            assert len(w) == 1
            assert "Using only 'new_namespace.key1'" in str(w[0].message)

        # And existing new namespace values are preserved
        assert data["new_namespace"]["key1"] == "new_value"
        assert "old_namespace" not in data

    def test_migrate_when_new_namespace_extends_old(self):
        """Test migration when new namespace extends old (e.g., 'settings' -> 'settings_good')."""
        # Given: An old namespace containing one key that belongs to the new namespace prefix
        data = {
            "settings": {"good_api_key": "secret1", "other_key": "value1"},
            "settings_good": {},
        }

        # When: Namespace migration is performed
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            migrate_deprecated_namespace(data, "settings", "settings_good")

            # Then: Only eligible keys are warned and migrated
            assert len(w) == 1
            assert "other_key" in str(w[0].message)

        # And only non-overlapping keys are migrated into the new namespace
        assert data["settings_good"] == {"other_key": "value1"}
        assert "settings" not in data

    def test_migrate_when_old_namespace_extends_new(self):
        """Test migration when old namespace extends new (e.g., 'settings_bad' -> 'settings')."""
        # Given: Old namespace keys and new namespace keys with old prefix artifacts
        data = {
            "settings_bad": {"api_key": "secret1", "bad_other_key": "value1"},
            "settings": {"bad_api_key": "secret2"},
        }

        # When: Namespace migration is performed
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            migrate_deprecated_namespace(data, "settings_bad", "settings")

            # Then: Migration emits at least one warning
            assert len(w) >= 1

        # And deprecated namespace is removed and bad prefixed keys are cleaned up
        assert "settings_bad" not in data
        assert data["settings"]["api_key"] == "secret1"
        assert "bad_api_key" not in data["settings"]

    def test_migrate_with_missing_old_namespace(self):
        """Test migration when old namespace doesn't exist."""
        # Given: Data without the deprecated namespace
        data = {"new_namespace": {"existing": "value"}}

        # When: Namespace migration is requested
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            migrate_deprecated_namespace(data, "old_namespace", "new_namespace")

            # Then: No warning is emitted
            assert len(w) == 0

        # And data remains unchanged
        assert data == {"new_namespace": {"existing": "value"}}


class TestMigrateDeprecatedVariable:
    """Test migrate_deprecated_variable function."""

    def test_migrate_with_empty_data(self):
        """Test migration with empty data dict."""
        # Given: An empty settings payload
        data: dict = {}

        # When: A deprecated variable migration is requested
        migrate_deprecated_variable(
            data, "old_var", "new_var", "current_namespace", "new_namespace"
        )

        # Then: The payload remains unchanged
        assert data == {}

    def test_migrate_with_none_data(self):
        """Test migration with None data."""
        # Given: A missing settings payload
        data = None

        # When: A deprecated variable migration is requested
        migrate_deprecated_variable(
            data, "old_var", "new_var", "current_namespace", "new_namespace"  # type: ignore
        )

        # Then: The payload remains None
        assert data is None

    def test_migrate_basic_variable(self):
        """Test basic variable migration within same namespace."""
        # Given: A namespace containing only a deprecated variable
        data = {
            "connector": {"old_var": "old_value"},
        }

        # When: The deprecated variable is migrated to its replacement
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            migrate_deprecated_variable(data, "old_var", "new_var", "connector", None)

            # Then: A migration warning is emitted
            assert len(w) == 1
            assert "Deprecated setting 'connector.old_var'" in str(w[0].message)
            assert "Migrating to 'connector.new_var'" in str(w[0].message)

        # And the old variable is removed and the new variable receives the value
        assert "old_var" not in data["connector"]
        assert data["connector"]["new_var"] == "old_value"

    def test_migrate_variable_to_different_namespace(self):
        """Test variable migration to different namespace."""
        # Given: A deprecated variable in one namespace and an empty target namespace
        data = {"old_namespace": {"old_var": "value"}, "new_namespace": {}}

        # When: The variable is migrated across namespaces
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            migrate_deprecated_variable(
                data, "old_var", "new_var", "old_namespace", "new_namespace"
            )

            # Then: Warning message includes old and new fully-qualified variable names
            assert len(w) == 1
            assert "old_namespace.old_var" in str(w[0].message)
            assert "new_namespace.new_var" in str(w[0].message)

        # And value is removed from old namespace and added to new namespace
        assert "old_var" not in data["old_namespace"]
        assert data["new_namespace"]["new_var"] == "value"

    def test_migrate_with_existing_new_variable(self):
        """Test migration when new variable already exists."""
        # Given: Both deprecated and replacement variables already exist
        data = {
            "connector": {"old_var": "old_value", "new_var": "new_value"},
        }

        # When: Variable migration is performed
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            migrate_deprecated_variable(data, "old_var", "new_var", "connector", None)

            # Then: Warning indicates only the replacement variable is used
            assert len(w) == 1
            assert "Using only 'connector.new_var'" in str(w[0].message)

        # And existing replacement value is preserved and deprecated variable removed
        assert data["connector"]["new_var"] == "new_value"
        assert "old_var" not in data["connector"]

    def test_migrate_with_value_transformation(self):
        """Test migration with value transformation function."""
        # Given: A deprecated string variable and a transformation function
        data = {"connector": {"old_var": "5"}}

        def new_value_factory(val):
            return int(val) * 2

        # When: Migration is performed with new_value_factory
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            migrate_deprecated_variable(
                data, "old_var", "new_var", "connector", None, new_value_factory
            )

        # Then: The replacement variable contains the transformed value
        assert data["connector"]["new_var"] == 10

    def test_migrate_with_missing_old_variable(self):
        """Test migration when old variable doesn't exist."""
        # Given: A namespace that does not contain the deprecated variable
        data = {"connector": {"other_var": "value"}}

        # When: Variable migration is requested
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            migrate_deprecated_variable(data, "old_var", "new_var", "connector", None)

            # Then: No warning is emitted
            assert len(w) == 0

        # And data remains unchanged
        assert data == {"connector": {"other_var": "value"}}

    def test_migrate_with_missing_namespace(self):
        """Test migration when namespace doesn't exist in data."""
        # Given: An empty payload with no target namespace
        data: dict = {}

        # When: Variable migration is requested
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            migrate_deprecated_variable(data, "old_var", "new_var", "connector", None)

            # Then: No warning is emitted
            assert len(w) == 0

        # And no namespace is created
        assert data == {}


class TestDeprecatedField:
    """Test DeprecatedField factory function."""

    def get_field_deprecate_annotation(self, field: FieldInfo) -> Deprecate | None:
        """Helper method to get Deprecate annotation from FieldInfo."""
        return next(
            (meta for meta in field.metadata if isinstance(meta, Deprecate)), None
        )

    def test_deprecated_field_with_deprecation(self):
        """Test DeprecatedField creates FieldInfo with deprecation."""
        # Given: A deprecation message for a deprecated field
        # When: The deprecated field is created with the deprecation message
        field = DeprecatedField(deprecated="Use new_field instead")

        # Then: Field metadata includes deprecation information
        assert isinstance(field, FieldInfo)
        assert field.deprecated == "Use new_field instead"
        # And a Deprecate annotation is present in the field metadata
        assert self.get_field_deprecate_annotation(field) is not None

    def test_deprecated_field_with_boolean_deprecation(self):
        """Test DeprecatedField with boolean deprecation flag."""
        # Given: A deprecetation boolean flag for a deprecated field
        # When: The deprecated field is created with the boolean flag
        field = DeprecatedField(deprecated=True)

        # Then: Field metadata includes deprecation flag
        assert isinstance(field, FieldInfo)
        assert field.deprecated is True
        # And a Deprecate annotation is present in the field metadata
        assert self.get_field_deprecate_annotation(field) is not None

    def test_deprecated_field_with_new_namespace(self):
        """Test DeprecatedField with new_namespace metadata."""
        # Given: A new namespace for a deprecated field
        # When: The deprecated field is created with the new_namespace argument
        field = DeprecatedField(
            deprecated="Moved to new_namespace", new_namespace="new_namespace"
        )

        # Then: Deprecate annotation exposes new_namespace value
        deprecate_annotation = self.get_field_deprecate_annotation(field)
        assert deprecate_annotation is not None
        assert deprecate_annotation.new_namespace == "new_namespace"

    def test_deprecated_field_with_new_namespaced_var(self):
        """Test DeprecatedField with new_namespaced_var metadata."""
        # Given: A new namespaced variable name for a deprecated field
        # When: The deprecated field is created with the new_namespaced_var argument
        field = DeprecatedField(
            deprecated="Renamed to new_var", new_namespaced_var="new_var"
        )

        # Then: Deprecate annotation exposes new_namespaced_var value
        deprecate_annotation = self.get_field_deprecate_annotation(field)
        assert deprecate_annotation is not None
        assert deprecate_annotation.new_namespaced_var == "new_var"

    def test_deprecated_field_with_new_value_factory(self):
        """Test DeprecatedField with new_value_factory function."""

        # Given: A function to transform the deprecated value for a deprecated field
        def transformer(val):
            return val * 2

        # When: The deprecated field is created with the new_value_factory argument
        field = DeprecatedField(deprecated=True, new_value_factory=transformer)

        # Then: Deprecate annotation exposes the provided factory function
        deprecate_annotation = self.get_field_deprecate_annotation(field)
        assert deprecate_annotation is not None
        assert deprecate_annotation.new_value_factory == transformer

    def test_deprecated_field_with_all_parameters(self):
        """Test DeprecatedField with all parameters."""

        def transformer(val):
            return val.upper()

        # Given: All migration metadata for a deprecated field
        # When: The deprecated field is created with all metadata arguments
        field = DeprecatedField(
            deprecated="Complete migration",
            new_namespace="new_ns",
            new_namespaced_var="new_var",
            new_value_factory=transformer,
        )

        # Then: Field and Deprecate annotation contain all provided metadata
        assert field.deprecated == "Complete migration"
        deprecate_annotation = self.get_field_deprecate_annotation(field)
        assert deprecate_annotation is not None
        assert deprecate_annotation.new_namespace == "new_ns"
        assert deprecate_annotation.new_namespaced_var == "new_var"
        assert deprecate_annotation.new_value_factory == transformer

    def test_deprecated_field_raises_when_deprecated_is_false(self):
        """Test DeprecatedField raises ValueError when deprecated is False."""
        # Given: An invalid DeprecatedField declaration with deprecated=False
        # When: DeprecatedField is created
        # Then: A ValueError is raised
        with pytest.raises(ValueError, match="DeprecatedField must have"):
            DeprecatedField(deprecated=False)  # type: ignore

    def test_deprecated_field_with_removal_date(self):
        """Test DeprecatedField with removal_date."""
        # Given: A removal date for a deprecated field
        # When: The deprecated field is created with the removal_date argument
        field = DeprecatedField(
            deprecated="This field is deprecated",
            new_namespaced_var="new_field",
            removal_date="2026-12-31",
        )

        # Then: Deprecate annotation includes removal date metadata
        deprecate_annotation = self.get_field_deprecate_annotation(field)
        assert deprecate_annotation is not None
        assert deprecate_annotation.removal_date == "2026-12-31"
        assert deprecate_annotation.new_namespaced_var == "new_field"

    def test_migrate_namespace_with_removal_date(self):
        """Test migrate_deprecated_namespace includes removal_date in warning."""
        # Given: A settings payload with deprecated namespace
        data = {
            "old_settings": {"key1": "value1", "key2": "value2"},
            "new_settings": {},
        }

        # When: Namespace migration is performed with removal_date argument
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            migrate_deprecated_namespace(
                data, "old_settings", "new_settings", removal_date="2026-12-31"
            )

            # Then: Warning messages include the removal date and migrated keys
            assert len(w) == 2
            warning_messages = [str(warning.message) for warning in w]
            assert any("2026-12-31" in msg for msg in warning_messages)
            assert any("key1" in msg for msg in warning_messages)

    def test_migrate_variable_with_removal_date(self):
        """Test migrate_deprecated_variable includes removal_date in warning."""
        # Given: A settings payload with a deprecated namespaced variable
        data = {
            "settings": {"old_var": "value", "other": "data"},
        }

        # When: Variable migration is performed with removal_date argument
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            migrate_deprecated_variable(
                data,
                "old_var",
                "new_var",
                "settings",
                removal_date="2026-06-30",
            )

            # Then: The warning message includes removal date and migration details
            assert len(w) == 1
            warning_msg = str(w[0].message)
            assert "2026-06-30" in warning_msg
            assert "old_var" in warning_msg
            assert "new_var" in warning_msg
