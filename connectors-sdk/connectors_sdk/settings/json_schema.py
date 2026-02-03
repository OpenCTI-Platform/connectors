"""JSON schema generation utilities for connector configurations."""

from copy import deepcopy
from typing import Any

from pydantic.json_schema import (
    GenerateJsonSchema,
    JsonSchemaValue,
)


class SanitizingJsonSchema(GenerateJsonSchema):
    """A JsonSchema generator that removes function references from schemas."""

    def generate_inner(self, schema: Any) -> JsonSchemaValue:
        """Generate inner schema, removing function references from metadata."""
        if isinstance(schema, dict):
            meta = schema.get("metadata")
            if isinstance(meta, dict):
                js_extra = meta.get("pydantic_js_extra")
                if isinstance(js_extra, dict) and "change_value" in js_extra:
                    schema = schema.copy()
                    meta = meta.copy()
                    js_extra = js_extra.copy()
                    js_extra.pop("change_value", None)
                    meta["pydantic_js_extra"] = js_extra
                    schema["metadata"] = meta

        return super().generate_inner(schema)


class ConnectorConfigJsonSchemaGenerator(SanitizingJsonSchema):
    """Flatten JSON schema generator for connector configurations."""

    connector_name: str

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the connector config JSON schema generator."""
        super().__init__(*args, **kwargs)

    @staticmethod
    def dereference_schema(schema_with_refs: dict[str, Any]) -> dict[str, Any]:
        """Dereference $ref pointers in JSON schema."""

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
    def flatten_config_loader_schema(root_schema: dict[str, Any]) -> dict[str, Any]:
        """Flatten config loader schema so all config vars are described at root level.

        :param root_schema: Original schema.
        :return: Flatten schema.
        """
        flat_json_schema = {
            "$schema": root_schema["$schema"],
            "$id": root_schema["$id"],
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": root_schema.get("additionalProperties", True),
        }

        for (
            config_loader_namespace_name,
            config_loader_namespace_schema,
        ) in root_schema["properties"].items():
            config_schema = config_loader_namespace_schema.get("properties", {})
            required_config_vars = config_loader_namespace_schema.get("required", [])
            deprecated_namespace = config_loader_namespace_schema.get("deprecated")
            new_namespace = config_loader_namespace_schema.get("new_namespace")
            for config_var_name, config_var_schema in config_schema.items():
                property_name = (
                    f"{config_loader_namespace_name.upper()}_{config_var_name.upper()}"
                )

                config_var_schema.pop("title", None)

                flat_json_schema["properties"][property_name] = config_var_schema

                if config_var_name in required_config_vars and not deprecated_namespace:
                    flat_json_schema["required"].append(property_name)

                if deprecated_namespace:
                    # Add deprecation info at property level
                    flat_json_schema["properties"][property_name]["deprecated"] = True
                    removal_date = config_loader_namespace_schema.get("removal_date")
                    removal_msg = (
                        f" (removal scheduled for {removal_date})"
                        if removal_date
                        else ""
                    )
                    if new_namespace:
                        if new_variable_name := config_var_schema.get(
                            "new_variable_name"
                        ):
                            if config_var_schema.get("new_namespace"):
                                new_namespace = config_var_schema.get("new_namespace")
                            flat_json_schema["properties"][property_name][
                                "description"
                            ] = f"Use {new_namespace.upper()}_{new_variable_name.upper()} instead.{removal_msg}"
                        else:
                            flat_json_schema["properties"][property_name][
                                "description"
                            ] = f"Use {new_namespace.upper()}_{config_var_name.upper()} instead.{removal_msg}"

                else:
                    if new_variable_name := config_var_schema.get("new_variable_name"):
                        new_namespace = (
                            config_var_schema.get("new_namespace")
                            or config_loader_namespace_name
                        )
                        removal_date = config_var_schema.get("removal_date")
                        removal_msg = (
                            f" (removal scheduled for {removal_date})"
                            if removal_date
                            else ""
                        )
                        flat_json_schema["properties"][property_name][
                            "description"
                        ] = f"Use {new_namespace.upper()}_{new_variable_name.upper()} instead.{removal_msg}"

                config_var_schema.pop("new_variable_name", None)
                config_var_schema.pop("new_namespace", None)
                config_var_schema.pop("removal_date", None)
        return flat_json_schema

    @staticmethod
    def filter_schema(schema: dict[str, Any]) -> dict[str, Any]:
        """Filter out CONNECTOR_ID from schema properties."""
        if "CONNECTOR_ID" in schema["properties"]:
            schema["properties"].pop("CONNECTOR_ID", None)
            schema["required"] = [
                r for r in schema.get("required", []) if r != "CONNECTOR_ID"
            ]
        return schema

    def generate(self, schema: Any, mode: str = "validation") -> dict[str, Any]:
        """Generate and process the JSON schema."""
        json_schema = super().generate(schema, mode=mode)  # type: ignore[arg-type]

        json_schema["$schema"] = self.schema_dialect
        json_schema["$id"] = (
            f"https://www.filigran.io/connectors/"
            f"{self.connector_name}_config.schema.json"
        )

        json_schema = self.dereference_schema(json_schema)
        json_schema = self.flatten_config_loader_schema(json_schema)
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
        null_schema = {"type": "null"}
        inner_json_schema = self.generate_inner(schema["schema"])

        if inner_json_schema == null_schema:
            return null_schema
        else:
            return inner_json_schema
