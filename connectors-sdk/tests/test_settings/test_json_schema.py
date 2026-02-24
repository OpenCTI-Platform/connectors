"""Tests for JSON schema generation utilities."""

import pytest
from connectors_sdk.settings.json_schema_generator import (
    ConnectorConfigJsonSchemaGenerator,
    SanitizedJsonSchemaGenerator,
)
from pydantic import BaseModel, Field


class TestSanitizingJsonSchema:
    """Test SanitizingJsonSchema class."""

    def test_removes_new_value_factory_from_metadata(self):
        """Test that new_value_factory function is removed from schema metadata."""

        class TestModel(BaseModel):
            field: str = Field(
                default="test",
                json_schema_extra={"new_value_factory": lambda x: x.upper()},
            )

        schema = TestModel.model_json_schema(
            schema_generator=SanitizedJsonSchemaGenerator
        )

        # Check that new_value_factory is not in the generated schema
        properties = schema["properties"]
        assert "new_value_factory" not in str(properties)

    def test_preserves_other_metadata(self):
        """Test that other metadata is preserved."""

        class TestModel(BaseModel):
            field: str = Field(
                default="test",
                json_schema_extra={
                    "new_namespace": "ns",
                    "new_namespaced_var": "var",
                    "new_value_factory": lambda x: x,
                },
            )

        schema = TestModel.model_json_schema(
            schema_generator=SanitizedJsonSchemaGenerator
        )

        # Other metadata should be preserved
        assert "new_namespace" in str(schema)
        assert "new_namespaced_var" in str(schema)

    def test_handles_schema_without_metadata(self):
        """Test handling schemas without metadata."""

        class TestModel(BaseModel):
            field: str = "test"

        schema = TestModel.model_json_schema(
            schema_generator=SanitizedJsonSchemaGenerator
        )

        assert "properties" in schema
        assert "field" in schema["properties"]

    def test_handles_nested_models(self):
        """Test handling nested models."""

        class NestedModel(BaseModel):
            nested_field: str = Field(
                default="test", json_schema_extra={"new_value_factory": lambda x: x}
            )

        class TestModel(BaseModel):
            nested: NestedModel = Field(default_factory=NestedModel)

        schema = TestModel.model_json_schema(
            schema_generator=SanitizedJsonSchemaGenerator
        )

        # Should not contain new_value_factory function
        assert "new_value_factory" not in str(schema)

    def test_generate_inner_with_function_in_metadata(self):
        """Test that generate_inner properly sanitizes metadata with functions."""

        class TestModel(BaseModel):
            field: str = Field(
                default="test",
                deprecated="Use new_field",
                json_schema_extra={
                    "new_namespaced_var": "new_field",
                    "new_value_factory": lambda x: x.upper(),
                },
            )

        schema = TestModel.model_json_schema(
            schema_generator=SanitizedJsonSchemaGenerator
        )

        # Check that schema is generated
        assert "properties" in schema
        assert "field" in schema["properties"]

        # new_value_factory should not appear in the string representation
        schema_str = str(schema)
        assert "new_value_factory" not in schema_str

        # But other metadata should be preserved
        assert "new_namespaced_var" in schema_str or "deprecated" in schema_str


class TestConnectorConfigJsonSchemaGenerator:
    """Test ConnectorConfigJsonSchemaGenerator class."""

    def test_dereference_simple_ref(self):
        """Test dereferencing simple $ref pointers."""
        schema_with_refs = {
            "$defs": {"SimpleType": {"type": "string", "description": "A string"}},
            "properties": {
                "field1": {"$ref": "#/$defs/SimpleType"},
            },
        }

        result = ConnectorConfigJsonSchemaGenerator.dereference_schema(schema_with_refs)

        assert result["properties"]["field1"]["type"] == "string"
        assert result["properties"]["field1"]["description"] == "A string"
        assert "$ref" not in result["properties"]["field1"]

    def test_dereference_nested_refs(self):
        """Test dereferencing nested $ref pointers."""
        schema_with_refs = {
            "$defs": {
                "BaseType": {"type": "string"},
                "ExtendedType": {
                    "allOf": [
                        {"$ref": "#/$defs/BaseType"},
                        {"minLength": 5},
                    ]
                },
            },
            "properties": {
                "field1": {"$ref": "#/$defs/ExtendedType"},
            },
        }

        result = ConnectorConfigJsonSchemaGenerator.dereference_schema(schema_with_refs)

        assert "allOf" in result["properties"]["field1"]

    def test_dereference_with_extra_properties(self):
        """Test that extra properties in ref are preserved."""
        schema_with_refs = {
            "$defs": {"SimpleType": {"type": "string"}},
            "properties": {
                "field1": {
                    "$ref": "#/$defs/SimpleType",
                    "description": "Custom description",
                },
            },
        }

        result = ConnectorConfigJsonSchemaGenerator.dereference_schema(schema_with_refs)

        assert result["properties"]["field1"]["type"] == "string"
        assert result["properties"]["field1"]["description"] == "Custom description"

    def test_dereference_invalid_ref_format(self):
        """Test handling invalid ref format."""
        schema_with_refs = {
            "properties": {
                "field1": {"$ref": "http://example.com/schema"},
            },
        }

        with pytest.raises(ValueError, match="Unsupported ref format"):
            ConnectorConfigJsonSchemaGenerator.dereference_schema(schema_with_refs)

    def test_to_environment_variable_schema_basic(self):
        """Test flattening basic config loader schema."""
        root_schema = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "$id": "test",
            "type": "object",
            "properties": {
                "opencti": {
                    "properties": {
                        "url": {"type": "string", "description": "OpenCTI URL"},
                        "token": {"type": "string", "description": "API token"},
                    },
                    "required": ["url", "token"],
                },
                "connector": {
                    "properties": {
                        "id": {"type": "string", "description": "Connector ID"},
                        "name": {"type": "string", "description": "Connector name"},
                    },
                    "required": ["id"],
                },
            },
        }

        result = ConnectorConfigJsonSchemaGenerator.to_environment_variable_schema(
            root_schema
        )

        # Check flattened properties
        assert "OPENCTI_URL" in result["properties"]
        assert "OPENCTI_TOKEN" in result["properties"]
        assert "CONNECTOR_ID" in result["properties"]
        assert "CONNECTOR_NAME" in result["properties"]

        # Check required fields
        assert "OPENCTI_URL" in result["required"]
        assert "OPENCTI_TOKEN" in result["required"]
        assert "CONNECTOR_ID" in result["required"]
        assert "CONNECTOR_NAME" not in result["required"]

        # Check descriptions
        assert result["properties"]["OPENCTI_URL"]["description"] == "OpenCTI URL"

    def test_flatten_with_deprecated_namespace(self):
        """Test flattening with deprecated namespace."""
        root_schema = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "$id": "test",
            "type": "object",
            "properties": {
                "old_namespace": {
                    "deprecated": True,
                    "new_namespace": "new_namespace",
                    "properties": {
                        "field": {"type": "string", "description": "A field"},
                    },
                    "required": ["field"],
                },
            },
        }

        result = ConnectorConfigJsonSchemaGenerator.to_environment_variable_schema(
            root_schema
        )

        # Deprecated namespace fields should not be required
        assert "OLD_NAMESPACE_FIELD" not in result["required"]
        # But should have deprecated marker
        assert result["properties"]["OLD_NAMESPACE_FIELD"]["deprecated"] is True
        # And migration hint
        assert (
            "NEW_NAMESPACE_FIELD"
            in result["properties"]["OLD_NAMESPACE_FIELD"]["description"]
        )

    def test_flatten_with_deprecated_namespace_and_field_level_new_namespace(self):
        """Test flattening with deprecated namespace where field has its own new_namespace."""
        root_schema = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "$id": "test",
            "type": "object",
            "properties": {
                "old_namespace": {
                    "deprecated": True,
                    "new_namespace": "new_namespace",
                    "properties": {
                        "field": {
                            "type": "string",
                            "description": "A field",
                            "new_namespaced_var": "renamed_field",
                            "new_namespace": "completely_different_namespace",
                        },
                    },
                    "required": ["field"],
                },
            },
        }

        result = ConnectorConfigJsonSchemaGenerator.to_environment_variable_schema(
            root_schema
        )

        # Should use the field-level new_namespace, not the namespace-level one
        assert (
            "COMPLETELY_DIFFERENT_NAMESPACE_RENAMED_FIELD"
            in result["properties"]["OLD_NAMESPACE_FIELD"]["description"]
        )

    def test_flatten_with_new_namespaced_var(self):
        """Test flattening with new_namespaced_var metadata."""
        root_schema = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "$id": "test",
            "type": "object",
            "properties": {
                "connector": {
                    "properties": {
                        "old_field": {
                            "type": "string",
                            "description": "Old field",
                            "deprecated": True,
                            "new_namespaced_var": "new_field",
                        },
                    },
                },
            },
        }

        result = ConnectorConfigJsonSchemaGenerator.to_environment_variable_schema(
            root_schema
        )

        # Should have migration hint
        assert (
            "CONNECTOR_NEW_FIELD"
            in result["properties"]["CONNECTOR_OLD_FIELD"]["description"]
        )

    def test_flatten_with_new_namespace_in_field(self):
        """Test flattening with new_namespace at field level."""
        root_schema = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "$id": "test",
            "type": "object",
            "properties": {
                "old_namespace": {
                    "properties": {
                        "field": {
                            "type": "string",
                            "description": "A field",
                            "deprecated": True,
                            "new_namespaced_var": "new_field",
                            "new_namespace": "new_namespace",
                        },
                    },
                },
            },
        }

        result = ConnectorConfigJsonSchemaGenerator.to_environment_variable_schema(
            root_schema
        )

        # Should use new_namespace from field
        assert (
            "NEW_NAMESPACE_NEW_FIELD"
            in result["properties"]["OLD_NAMESPACE_FIELD"]["description"]
        )

    def test_flatten_removes_title(self):
        """Test that title is removed from flattened properties."""
        root_schema = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "$id": "test",
            "type": "object",
            "properties": {
                "connector": {
                    "properties": {
                        "field": {
                            "type": "string",
                            "title": "Field Title",
                            "description": "Field description",
                        },
                    },
                },
            },
        }

        result = ConnectorConfigJsonSchemaGenerator.to_environment_variable_schema(
            root_schema
        )

        # Title should be removed
        assert "title" not in result["properties"]["CONNECTOR_FIELD"]
        assert (
            result["properties"]["CONNECTOR_FIELD"]["description"]
            == "Field description"
        )

    def test_flatten_removes_metadata_fields(self):
        """Test that new_namespaced_var and new_namespace are removed from final schema."""
        root_schema = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "$id": "test",
            "type": "object",
            "properties": {
                "connector": {
                    "properties": {
                        "field": {
                            "type": "string",
                            "new_namespaced_var": "new_field",
                            "new_namespace": "new_ns",
                        },
                    },
                },
            },
        }

        result = ConnectorConfigJsonSchemaGenerator.to_environment_variable_schema(
            root_schema
        )

        # Metadata fields should be removed
        assert "new_namespaced_var" not in result["properties"]["CONNECTOR_FIELD"]
        assert "new_namespace" not in result["properties"]["CONNECTOR_FIELD"]

    def test_filter_schema_removes_connector_id(self):
        """Test that CONNECTOR_ID is removed from schema."""
        schema = {
            "properties": {
                "CONNECTOR_ID": {"type": "string"},
                "CONNECTOR_NAME": {"type": "string"},
            },
            "required": ["CONNECTOR_ID", "CONNECTOR_NAME"],
        }

        result = ConnectorConfigJsonSchemaGenerator.filter_schema(schema)

        assert "CONNECTOR_ID" not in result["properties"]
        assert "CONNECTOR_ID" not in result["required"]
        assert "CONNECTOR_NAME" in result["properties"]
        assert "CONNECTOR_NAME" in result["required"]

    def test_filter_schema_preserves_other_fields(self):
        """Test that other fields are preserved."""
        schema = {
            "properties": {
                "OPENCTI_URL": {"type": "string"},
                "OPENCTI_TOKEN": {"type": "string"},
            },
            "required": ["OPENCTI_URL"],
        }

        result = ConnectorConfigJsonSchemaGenerator.filter_schema(schema)

        assert result == schema

    def test_generate_full_pipeline(self):
        """Test complete schema generation pipeline."""

        class NestedConfig(BaseModel):
            url: str = Field(description="URL")
            token: str = Field(description="Token")

        class TestSettings(BaseModel):
            opencti: NestedConfig = Field(default_factory=NestedConfig)

        # Create generator with connector name
        class TestGenerator(ConnectorConfigJsonSchemaGenerator):
            connector_name = "test-connector"

        schema = TestSettings.model_json_schema(schema_generator=TestGenerator)

        # Check schema structure
        assert "$schema" in schema
        assert "$id" in schema
        assert "test-connector" in schema["$id"]
        assert "properties" in schema
        assert "OPENCTI_URL" in schema["properties"]
        assert "OPENCTI_TOKEN" in schema["properties"]

    def test_nullable_schema_implementation(self):
        """Test that nullable_schema method exists and can be called."""
        from unittest.mock import patch

        class TestGenerator(ConnectorConfigJsonSchemaGenerator):
            connector_name = "test"

        generator = TestGenerator()

        # Mock generate_inner to avoid Pydantic internal complexity
        with patch.object(generator, "generate_inner") as mock_generate_inner:
            # Test case 1: When generate_inner returns null schema
            mock_generate_inner.return_value = {"type": "null"}
            result = generator.nullable_schema({"schema": {}})
            assert result == {"type": "null"}

            # Test case 2: When generate_inner returns non-null schema
            mock_generate_inner.return_value = {"type": "string"}
            result = generator.nullable_schema({"schema": {}})
            assert result == {"type": "string"}

    def test_init_with_connector_name(self):
        """Test initialization with connector_name class attribute."""

        class TestGenerator(ConnectorConfigJsonSchemaGenerator):
            connector_name = "my-connector"

        generator = TestGenerator()
        assert generator.connector_name == "my-connector"

    def test_flatten_with_removal_date_on_deprecated_namespace(self):
        """Test that removal_date appears in description for deprecated namespace."""
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "test",
            "type": "object",
            "properties": {
                "old_namespace": {
                    "type": "object",
                    "deprecated": True,
                    "new_namespace": "new_namespace",
                    "removal_date": "2026-12-31",
                    "properties": {
                        "field1": {"type": "string"},
                        "field2": {"type": "integer"},
                    },
                    "required": ["field1"],
                },
            },
        }

        result = ConnectorConfigJsonSchemaGenerator.to_environment_variable_schema(
            schema
        )

        # Check that removal_date is in the description
        assert "OLD_NAMESPACE_FIELD1" in result["properties"]
        description1 = result["properties"]["OLD_NAMESPACE_FIELD1"]["description"]
        assert "2026-12-31" in description1
        assert "removal scheduled for 2026-12-31" in description1
        assert "NEW_NAMESPACE_FIELD1" in description1

    def test_flatten_with_removal_date_on_field(self):
        """Test that removal_date appears in description for deprecated field."""
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "test",
            "type": "object",
            "properties": {
                "namespace": {
                    "type": "object",
                    "properties": {
                        "old_field": {
                            "type": "string",
                            "new_namespaced_var": "new_field",
                            "removal_date": "2026-06-30",
                        },
                        "new_field": {"type": "string"},
                    },
                },
            },
        }

        result = ConnectorConfigJsonSchemaGenerator.to_environment_variable_schema(
            schema
        )

        # Check that removal_date is in the description
        assert "NAMESPACE_OLD_FIELD" in result["properties"]
        description = result["properties"]["NAMESPACE_OLD_FIELD"]["description"]
        assert "2026-06-30" in description
        assert "removal scheduled for 2026-06-30" in description
        assert "NAMESPACE_NEW_FIELD" in description

    def test_flatten_without_removal_date(self):
        """Test that description works correctly without removal_date."""
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "test",
            "type": "object",
            "properties": {
                "old_namespace": {
                    "type": "object",
                    "deprecated": True,
                    "new_namespace": "new_namespace",
                    "properties": {
                        "field1": {"type": "string"},
                    },
                },
            },
        }

        result = ConnectorConfigJsonSchemaGenerator.to_environment_variable_schema(
            schema
        )

        # Check that description exists but without removal_date
        assert "OLD_NAMESPACE_FIELD1" in result["properties"]
        description = result["properties"]["OLD_NAMESPACE_FIELD1"]["description"]
        assert "NEW_NAMESPACE_FIELD1" in description
        assert "removal scheduled" not in description
