"""
This script is used for generating a JSON schema model purpose.
Make sure to define or import ConfigLoader and ensure it is compatible (e.g., a Pydantic model).
The code assumes that the __infos__ directory exists and contains the necessary JSON files.
All methods are documented for clarity and maintainability.
The print statement in create_connector_config_json_schema provides positive feedback when the contract is generated.
The connector configuration MUST use `pydantic` or `pydantic-settings` Python libraries.
"""

import errno
import json
import os
import sys
import traceback
from copy import deepcopy
from typing import override

from pydantic.json_schema import GenerateJsonSchema

sys.path.append(os.path.join(os.path.dirname(__file__), "src"))

__CONNECTOR_METADATA_DIRECTORY__ = "__metadata__"
__CONNECTOR_CONFIG_JSON_SCHEMA_FILENAME__ = "connector_config_schema.json"

# attributes filtered from the connector configuration before generating the manifest
__FILTERED_ATTRIBUTES__ = [
    # connector id is generated
    "CONNECTOR_ID",
    # Deprecated in favor of CONNECTOR_DURATION_PERIOD
    "MITRE_INTERVAL",
    "CVE_INTERVAL"
]

def get_connector_config_schema_generator(connector_name: str) -> GenerateJsonSchema:
    class ConnectorConfigSchemaGenerator(GenerateJsonSchema):
        @staticmethod
        def dereference_schema(schema_with_refs):
            """Return a new schema with all internal $ref resolved."""

            def _resolve(schema, root):
                if isinstance(schema, dict):
                    if "$ref" in schema:
                        ref_path = schema["$ref"]
                        if ref_path.startswith("#/$defs/"):
                            def_name = ref_path.split("/")[-1]
                            # Deep copy to avoid mutating $defs
                            resolved = deepcopy(root["$defs"][def_name])
                            return _resolve(resolved, root)
                        else:
                            raise ValueError(f"Unsupported ref format: {ref_path}")
                    else:
                        return {
                            schema_key: _resolve(schema_value, root)
                            for schema_key, schema_value in schema.items()
                        }
                elif isinstance(schema, list):
                    return [_resolve(item, root) for item in schema]
                else:
                    return schema

            return _resolve(deepcopy(schema_with_refs), schema_with_refs)

        @staticmethod
        def flatten_config_loader_schema(root_schema: dict):
            """
            Flatten config loader schema so all config vars are described at root level.

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
                required_config_vars = config_loader_namespace_schema.get(
                    "required", []
                )

                for config_var_name, config_var_schema in config_schema.items():
                    property_name = f"{config_loader_namespace_name.upper()}_{config_var_name.upper()}"

                    config_var_schema.pop("title", None)

                    flat_json_schema["properties"][property_name] = config_var_schema

                    if config_var_name in required_config_vars:
                        flat_json_schema["required"].append(property_name)

            return flat_json_schema

        @staticmethod
        def filter_schema(schema):
            for filtered_attribute in __FILTERED_ATTRIBUTES__:
                if filtered_attribute in schema["properties"]:
                    del schema["properties"][filtered_attribute]
            return schema

        @override
        def generate(self, schema, mode="validation"):
            json_schema = super().generate(schema, mode=mode)

            json_schema["$schema"] = self.schema_dialect
            json_schema["$id"] = (
                f"https://www.filigran.io/connectors/{connector_name}_config.schema.json"
            )
            dereferenced_schema = self.dereference_schema(json_schema)
            flattened_schema = self.flatten_config_loader_schema(dereferenced_schema)
            return self.filter_schema(flattened_schema)

        @override
        def nullable_schema(self, schema):
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

    return ConnectorConfigSchemaGenerator


class ConnectorContractGenerator:
    """
    Specifications of the generator

    This class encapsulates the main actions to generate a connector contract.
    """

    def __init__(self):
        try:  # Import from a packaged connector (with `src/__main__.py`)
            from src import ConfigLoader
        except ImportError as err:
            try:  # Import from a connector following our templates (with `src/main.py`)
                from src.main import ConfigLoader
            except ImportError:
                raise err

        self.connector_name = os.path.basename(os.path.dirname(__file__))
        self.connector_config_loader = (
            ConfigLoader  # Should be a Pydantic model or config loader
        )

        self._create_metadata_directory()

    @staticmethod
    def _create_metadata_directory():
        """
        Ensure __metadata__ directory exists to write the config JSON schema in it.
        """
        path = os.path.join(os.path.dirname(__file__), __CONNECTOR_METADATA_DIRECTORY__)

        try:
            os.makedirs(path)
        except OSError as exc:
            if exc.errno == errno.EEXIST and os.path.isdir(path):
                pass  # do not raise error if the directory already exists
            else:
                raise

    def generate_connector_config_schema(self):
        """
        Generates the complete connector schema using a custom schema generator compatible with Pydantic.
        Isolate custom class generator, Pydantic expects a class, not an instance
        Always subclass GenerateJsonSchema and pass the class to Pydantic, not an instance
        :return: The generated connector schema as a dictionary.
        """
        schema_generator = get_connector_config_schema_generator(self.connector_name)

        return self.connector_config_loader.model_json_schema(
            by_alias=False,
            schema_generator=schema_generator,
            mode="validation",
        )

    def create_connector_config_json_schema(self):
        """
        Generates the connector contract and writes it to a JSON file.
        """
        connector_config_json_schema = self.generate_connector_config_schema()

        filepath = os.path.join(
            os.path.dirname(__file__),
            __CONNECTOR_METADATA_DIRECTORY__,
            __CONNECTOR_CONFIG_JSON_SCHEMA_FILENAME__,
        )
        with open(filepath, "w") as file:
            connector_config_json_schema_json = json.dumps(
                connector_config_json_schema, indent=2
            )
            file.write(connector_config_json_schema_json)

        print(f"✅ Connector config JSON schema written to {filepath}")


if __name__ == "__main__":
    """
    Entry point of the script
    """
    try:
        connector_config_json_schema_generator = ConnectorContractGenerator()
        connector_config_json_schema_generator.create_connector_config_json_schema()
    except Exception:
        traceback.print_exc()
        exit(1)
