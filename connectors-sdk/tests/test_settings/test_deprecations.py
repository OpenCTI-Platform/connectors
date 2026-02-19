"""Tests for deprecation utilities."""

import warnings

import pytest
from connectors_sdk.settings.deprecations import (
    DeprecatedField,
    migrate_deprecated_namespace,
    migrate_deprecated_variable,
)
from pydantic.fields import FieldInfo


class TestMigrateDeprecatedNamespace:
    """Test migrate_deprecated_namespace function."""

    def test_migrate_with_empty_data(self):
        """Test migration with empty data dict."""
        data: dict = {}
        migrate_deprecated_namespace(data, "old_ns", "new_ns")
        assert data == {}

    def test_migrate_with_none_data(self):
        """Test migration with None data."""
        data = None
        migrate_deprecated_namespace(data, "old_ns", "new_ns")  # type: ignore
        assert data is None

    def test_migrate_basic_namespace(self):
        """Test basic namespace migration."""
        data = {
            "old_namespace": {"key1": "value1", "key2": "value2"},
            "new_namespace": {},
        }

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            migrate_deprecated_namespace(data, "old_namespace", "new_namespace")

            # Check warnings
            assert len(w) == 2
            assert "Deprecated setting 'old_namespace.key1'" in str(w[0].message)
            assert "Migrating to 'new_namespace.key1'" in str(w[0].message)
            assert "Deprecated setting 'old_namespace.key2'" in str(w[1].message)

        # Check migration
        assert "old_namespace" not in data
        assert data["new_namespace"] == {"key1": "value1", "key2": "value2"}

    def test_migrate_with_existing_keys_in_new_namespace(self):
        """Test migration when keys already exist in new namespace."""
        data = {
            "old_namespace": {"key1": "old_value"},
            "new_namespace": {"key1": "new_value"},
        }

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            migrate_deprecated_namespace(data, "old_namespace", "new_namespace")

            # Should warn about using only new value
            assert len(w) == 1
            assert "Using only 'new_namespace.key1'" in str(w[0].message)

        # New value should be preserved
        assert data["new_namespace"]["key1"] == "new_value"
        assert "old_namespace" not in data

    def test_migrate_when_new_namespace_extends_old(self):
        """Test migration when new namespace extends old (e.g., 'settings' -> 'settings_good')."""
        data = {
            "settings": {"good_api_key": "secret1", "other_key": "value1"},
            "settings_good": {},
        }

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            migrate_deprecated_namespace(data, "settings", "settings_good")

            # Should not migrate 'good_api_key' as it belongs to new namespace
            assert len(w) == 1
            assert "other_key" in str(w[0].message)

        # Only other_key should be migrated
        assert data["settings_good"] == {"other_key": "value1"}
        assert "settings" not in data

    def test_migrate_when_old_namespace_extends_new(self):
        """Test migration when old namespace extends new (e.g., 'settings_bad' -> 'settings')."""
        data = {
            "settings_bad": {"api_key": "secret1", "bad_other_key": "value1"},
            "settings": {"bad_api_key": "secret2"},
        }

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            migrate_deprecated_namespace(data, "settings_bad", "settings")

            # Should migrate and cleanup wrong prefixed keys
            assert len(w) >= 1

        # Check migration and cleanup
        assert "settings_bad" not in data
        assert data["settings"]["api_key"] == "secret1"
        assert "bad_api_key" not in data["settings"]

    def test_migrate_with_missing_old_namespace(self):
        """Test migration when old namespace doesn't exist."""
        data = {"new_namespace": {"existing": "value"}}

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            migrate_deprecated_namespace(data, "old_namespace", "new_namespace")

            # Should not warn
            assert len(w) == 0

        # Should not change data
        assert data == {"new_namespace": {"existing": "value"}}


class TestMigrateDeprecatedVariable:
    """Test migrate_deprecated_variable function."""

    def test_migrate_with_empty_data(self):
        """Test migration with empty data dict."""
        data: dict = {}
        migrate_deprecated_variable(
            data, "old_var", "new_var", "current_namespace", "new_namespace"
        )
        assert data == {}

    def test_migrate_with_none_data(self):
        """Test migration with None data."""
        data = None
        migrate_deprecated_variable(
            data, "old_var", "new_var", "current_namespace", "new_namespace"  # type: ignore
        )
        assert data is None

    def test_migrate_basic_variable(self):
        """Test basic variable migration within same namespace."""
        data = {
            "connector": {"old_var": "old_value"},
        }

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            migrate_deprecated_variable(data, "old_var", "new_var", "connector", None)

            # Check warnings
            assert len(w) == 1
            assert "Deprecated setting 'connector.old_var'" in str(w[0].message)
            assert "Migrating to 'connector.new_var'" in str(w[0].message)

        # Check migration
        assert "old_var" not in data["connector"]
        assert data["connector"]["new_var"] == "old_value"

    def test_migrate_variable_to_different_namespace(self):
        """Test variable migration to different namespace."""
        data = {"old_namespace": {"old_var": "value"}, "new_namespace": {}}

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            migrate_deprecated_variable(
                data, "old_var", "new_var", "old_namespace", "new_namespace"
            )

            # Check warnings
            assert len(w) == 1
            assert "old_namespace.old_var" in str(w[0].message)
            assert "new_namespace.new_var" in str(w[0].message)

        # Check migration
        assert "old_var" not in data["old_namespace"]
        assert data["new_namespace"]["new_var"] == "value"

    def test_migrate_with_existing_new_variable(self):
        """Test migration when new variable already exists."""
        data = {
            "connector": {"old_var": "old_value", "new_var": "new_value"},
        }

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            migrate_deprecated_variable(data, "old_var", "new_var", "connector", None)

            # Should warn about using only new value
            assert len(w) == 1
            assert "Using only 'connector.new_var'" in str(w[0].message)

        # New value should be preserved
        assert data["connector"]["new_var"] == "new_value"
        assert "old_var" not in data["connector"]

    def test_migrate_with_value_transformation(self):
        """Test migration with value transformation function."""
        data = {"connector": {"old_var": "5"}}

        def new_value_factory(val):
            return int(val) * 2

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            migrate_deprecated_variable(
                data, "old_var", "new_var", "connector", None, new_value_factory
            )

        # Check value transformation
        assert data["connector"]["new_var"] == 10

    def test_migrate_with_missing_old_variable(self):
        """Test migration when old variable doesn't exist."""
        data = {"connector": {"other_var": "value"}}

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            migrate_deprecated_variable(data, "old_var", "new_var", "connector", None)

            # Should not warn
            assert len(w) == 0

        # Should not change data
        assert data == {"connector": {"other_var": "value"}}

    def test_migrate_with_missing_namespace(self):
        """Test migration when namespace doesn't exist in data."""
        data: dict = {}

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            migrate_deprecated_variable(data, "old_var", "new_var", "connector", None)

            # Should not warn
            assert len(w) == 0

        # Should not add namespace
        assert data == {}


class TestDeprecatedField:
    """Test DeprecatedField factory function."""

    def test_deprecated_field_with_deprecation(self):
        """Test DeprecatedField creates FieldInfo with deprecation."""
        field = DeprecatedField(deprecated="Use new_field instead")

        assert isinstance(field, FieldInfo)
        assert field.deprecated == "Use new_field instead"
        assert field.default is None

    def test_deprecated_field_with_boolean_deprecation(self):
        """Test DeprecatedField with boolean deprecation flag."""
        field = DeprecatedField(deprecated=True)

        assert isinstance(field, FieldInfo)
        assert field.deprecated is True

    def test_deprecated_field_with_new_namespace(self):
        """Test DeprecatedField with new_namespace metadata."""
        field = DeprecatedField(
            deprecated="Moved to new_namespace", new_namespace="new_namespace"
        )

        assert field.json_schema_extra["new_namespace"] == "new_namespace"  # type: ignore

    def test_deprecated_field_with_new_namespaced_var(self):
        """Test DeprecatedField with new_namespaced_var metadata."""
        field = DeprecatedField(
            deprecated="Renamed to new_var", new_namespaced_var="new_var"
        )

        assert field.json_schema_extra["new_namespaced_var"] == "new_var"  # type: ignore

    def test_deprecated_field_with_new_value_factory(self):
        """Test DeprecatedField with new_value_factory function."""

        def transformer(val):
            return val * 2

        field = DeprecatedField(deprecated=True, new_value_factory=transformer)

        assert field.json_schema_extra["new_value_factory"] == transformer  # type: ignore

    def test_deprecated_field_with_all_parameters(self):
        """Test DeprecatedField with all parameters."""

        def transformer(val):
            return val.upper()

        field = DeprecatedField(
            deprecated="Complete migration",
            new_namespace="new_ns",
            new_namespaced_var="new_var",
            new_value_factory=transformer,
        )

        assert field.deprecated == "Complete migration"
        assert field.json_schema_extra["new_namespace"] == "new_ns"  # type: ignore
        assert field.json_schema_extra["new_namespaced_var"] == "new_var"  # type: ignore
        assert field.json_schema_extra["new_value_factory"] == transformer  # type: ignore

    def test_deprecated_field_default_none(self):
        """Test DeprecatedField always sets default to None."""
        field = DeprecatedField(deprecated=True)

        assert field.default is None

    def test_deprecated_field_raises_when_deprecated_is_false(self):
        """Test DeprecatedField raises ValueError when deprecated is False."""
        with pytest.raises(ValueError, match="DeprecatedField must have"):
            DeprecatedField(deprecated=False)

    def test_deprecated_field_with_removal_date(self):
        """Test DeprecatedField with removal_date."""
        field = DeprecatedField(
            deprecated="This field is deprecated",
            new_namespaced_var="new_field",
            removal_date="2026-12-31",
        )

        assert field.json_schema_extra["removal_date"] == "2026-12-31"  # type: ignore
        assert field.json_schema_extra["new_namespaced_var"] == "new_field"  # type: ignore

    def test_migrate_namespace_with_removal_date(self):
        """Test migrate_deprecated_namespace includes removal_date in warning."""
        data = {
            "old_settings": {"key1": "value1", "key2": "value2"},
            "new_settings": {},
        }

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            migrate_deprecated_namespace(
                data, "old_settings", "new_settings", removal_date="2026-12-31"
            )

            # Should have warnings with removal date
            assert len(w) == 2
            warning_messages = [str(warning.message) for warning in w]
            assert any("2026-12-31" in msg for msg in warning_messages)
            assert any("key1" in msg for msg in warning_messages)

    def test_migrate_variable_with_removal_date(self):
        """Test migrate_deprecated_variable includes removal_date in warning."""
        data = {
            "settings": {"old_var": "value", "other": "data"},
        }

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            migrate_deprecated_variable(
                data,
                "old_var",
                "new_var",
                "settings",
                removal_date="2026-06-30",
            )

            # Should have warning with removal date
            assert len(w) == 1
            warning_msg = str(w[0].message)
            assert "2026-06-30" in warning_msg
            assert "old_var" in warning_msg
            assert "new_var" in warning_msg
