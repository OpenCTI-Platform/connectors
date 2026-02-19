"""JSON schema generation utilities for connector configurations."""

from copy import deepcopy
from typing import Any

from pydantic.json_schema import (
    GenerateJsonSchema,
    JsonSchemaValue,
)


class SanitizedJsonSchemaGenerator(GenerateJsonSchema):
    """A JsonSchema generator that removes function references from schemas."""

    def generate_inner(self, schema: Any) -> JsonSchemaValue:
        """Generate inner schema, removing function references from metadata.

        Args:
            schema: The schema to process.

        Returns:
            The processed JSON schema value.
        """
        if (
            not isinstance(schema, dict)
            or not isinstance(meta := schema.get("metadata"), dict)
            or not isinstance(js_extra := meta.get("pydantic_js_extra"), dict)
            or "new_value_factory" not in js_extra
        ):
            return super().generate_inner(schema)

        schema = schema.copy()
        meta = meta.copy()
        js_extra = js_extra.copy()
        js_extra.pop("new_value_factory", None)
        meta["pydantic_js_extra"] = js_extra
        schema["metadata"] = meta

        return super().generate_inner(schema)


class ConnectorConfigJsonSchemaGenerator(SanitizedJsonSchemaGenerator):
    """Generate JSON schemas for connector configurations with resolved references and deprecation handling."""

    connector_name: str

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the connector config JSON schema generator."""
        super().__init__(*args, **kwargs)

    @staticmethod
    def dereference_schema(schema_with_refs: dict[str, Any]) -> dict[str, Any]:
        """Resolve $ref pointers in JSON schema to inline definitions.

        Args:
            schema_with_refs: Schema containing $ref pointers.

        Returns:
            Schema with all $ref pointers resolved to their definitions.
        """

        def _resolve(schema: Any, root: dict[str, Any]) -> Any:
            if isinstance(schema, dict):
                if "$ref" in schema:
                    ref_path = schema["$ref"]
                    if ref_path.startswith("#/$defs/"):
                        def_name = ref_path.split("/")[-1]
                        resolved = deepcopy(root["$defs"][def_name])
                        resolved_obj = _resolve(resolved, root)
                        extra = {k: v for k, v in schema.items() if k != "$ref"}
                        return {**resolved_obj, **extra}
                    raise ValueError(f"Unsupported ref format: {ref_path}")
                return {k: _resolve(v, root) for k, v in schema.items()}
            if isinstance(schema, list):
                return [_resolve(v, root) for v in schema]
            return schema

        return _resolve(deepcopy(schema_with_refs), schema_with_refs)  # type: ignore[no-any-return]

    @staticmethod
    def to_environment_variable_schema(root_schema: dict[str, Any]) -> dict[str, Any]:
        """Convert nested namespace-based configuration schema to environment variable format.

        Transforms the configuration schema to merge nested namespace properties into root-level
        properties using NAMESPACE_VARIABLE naming convention, enabling flat representation of
        configuration as environment variables. Also processes and preserves deprecation metadata.

        Args:
            root_schema: Original schema with nested namespaces.

        Returns:
            Schema with properties at root level using NAMESPACE_VARIABLE naming.
        """
        environment_variable_schema = {
            "$schema": root_schema["$schema"],
            "$id": root_schema["$id"],
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": root_schema.get("additionalProperties", True),
        }

        for (
            connector_settings_namespace_name,
            connector_settings_namespace_schema,
        ) in root_schema["properties"].items():
            config_schema = connector_settings_namespace_schema.get("properties", {})
            required_config_vars = connector_settings_namespace_schema.get(
                "required", []
            )
            deprecated_namespace = connector_settings_namespace_schema.get("deprecated")
            new_namespace = connector_settings_namespace_schema.get("new_namespace")
            for config_var_name, config_var_schema in config_schema.items():
                property_name = f"{connector_settings_namespace_name.upper()}_{config_var_name.upper()}"

                config_var_schema.pop("title", None)

                environment_variable_schema["properties"][
                    property_name
                ] = config_var_schema

                if config_var_name in required_config_vars and not deprecated_namespace:
                    environment_variable_schema["required"].append(property_name)

                if deprecated_namespace:
                    # Add deprecation info at property level
                    config_var_schema["deprecated"] = True
                    removal_date = connector_settings_namespace_schema.get(
                        "removal_date"
                    )
                    removal_msg = (
                        f" (removal scheduled for {removal_date})"
                        if removal_date
                        else ""
                    )
                    if new_namespace:
                        if new_namespaced_var := config_var_schema.get(
                            "new_namespaced_var"
                        ):
                            if config_var_schema.get("new_namespace"):
                                new_namespace = config_var_schema.get("new_namespace")
                            config_var_schema["description"] = (
                                f"Use {new_namespace.upper()}_{new_namespaced_var.upper()} instead.{removal_msg}"
                            )
                        else:
                            config_var_schema["description"] = (
                                f"Use {new_namespace.upper()}_{config_var_name.upper()} instead.{removal_msg}"
                            )

                else:
                    if new_namespaced_var := config_var_schema.get(
                        "new_namespaced_var"
                    ):
                        new_namespace = (
                            config_var_schema.get("new_namespace")
                            or connector_settings_namespace_name
                        )
                        removal_date = config_var_schema.get("removal_date")
                        removal_msg = (
                            f" (removal scheduled for {removal_date})"
                            if removal_date
                            else ""
                        )
                        config_var_schema["description"] = (
                            f"Use {new_namespace.upper()}_{new_namespaced_var.upper()} instead.{removal_msg}"
                        )

                config_var_schema.pop("new_namespaced_var", None)
                config_var_schema.pop("new_namespace", None)
                config_var_schema.pop("removal_date", None)
        return environment_variable_schema

    # TO DO: remove this function when it's handle on opencti side
    @staticmethod
    def filter_schema(schema: dict[str, Any]) -> dict[str, Any]:
        """Remove CONNECTOR_ID from schema properties and required fields.

        Args:
            schema: The schema to filter.

        Returns:
            Filtered schema without CONNECTOR_ID.
        """
        if "CONNECTOR_ID" in schema["properties"]:
            schema["properties"].pop("CONNECTOR_ID")
            schema["required"] = [
                r for r in schema.get("required", []) if r != "CONNECTOR_ID"
            ]
        return schema

    def generate(self, schema: Any, mode: str = "validation") -> dict[str, Any]:
        """Generate and process the connector configuration JSON schema.

        Combines schema generation, reference resolution, namespace conversion to environment
        variable format, and cleanup filtering.

        Args:
            schema: The Pydantic schema to process.
            mode: The generation mode (default: 'validation').

        Returns:
            Complete JSON schema for connector configuration.
        """
        json_schema = super().generate(schema, mode=mode)  # type: ignore[arg-type]

        json_schema["$schema"] = self.schema_dialect
        json_schema["$id"] = (
            f"https://www.filigran.io/connectors/"
            f"{self.connector_name}_config.schema.json"
        )

        json_schema = self.dereference_schema(json_schema)
        json_schema = self.to_environment_variable_schema(json_schema)
        return self.filter_schema(json_schema)

    def nullable_schema(self, schema: Any) -> JsonSchemaValue:
        """Generates a JSON schema that matches a schema that allows null values.

        Args:
            schema: The core schema.

        Returns:
            The generated JSON schema.

        Notes:
            This method overrides `GenerateJsonSchema.nullable_schema` to generate schemas without `anyOf` keyword.
        """
        return self.generate_inner(schema["schema"])
