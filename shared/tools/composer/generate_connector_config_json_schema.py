"""
This script is used for generating a JSON schema model purpose.
Make sure to define or import ConfigLoader and ensure it is compatible (e.g., a Pydantic model).
The code assumes that the __infos__ directory exists and contains the necessary JSON files.
All methods are documented for clarity and maintainability.
The print statement in create_connector_config_json_schema provides positive feedback when the contract is generated.
The connector configuration MUST use `pydantic` or `pydantic-settings` Python libraries.
"""
import traceback
import json
import os

from pydantic.json_schema import GenerateJsonSchema
# Import your configuration model
from src import ConfigLoader

__CONNECTOR_CONFIG_JSON_SCHEMA_FILENAME__ = "connector_config_schema.json"


class ConnectorContractGenerator:
    """
    Specifications of the generator

    This class encapsulates the main actions to generate a connector contract.
    """

    def __init__(self):
        self.connector_name = os.path.basename(os.path.dirname(__file__))
        self.connector_config_loader = ConfigLoader  # Should be a Pydantic model or config loader

    @staticmethod
    def flatten_config_loader_schema(root_schema: dict, schema_defs: dict):
        """
        Flatten config loader schema so all config vars are described at root level.

        :param definitions: Dictionary of configuration definitions.
        :return: Dictionary with 'properties' and 'required' keys.
        """
        flat_json_schema =  {
            "$schema": root_schema["$schema"],
            "$id": root_schema["$id"],
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": root_schema.get("additionalProperties", True),
        }

        for config_loader_namespace_schema in schema_defs.values():
            config_vars_schema = config_loader_namespace_schema.get("properties", {})
            for config_var_name, config_var_schema in config_vars_schema.items():
                config_var_schema.pop("title", None) # ? why removing title ? useful for generating the env vars table in README
                flat_json_schema["properties"][config_var_name] = config_var_schema

            flat_json_schema["required"].extend(config_loader_namespace_schema.get("required", []))

        return flat_json_schema

    def generate_connector_config_vars_schema(self):
        """
        Generates the complete connector schema using a custom schema generator compatible with Pydantic.
        Isolate custom class generator, Pydantic expects a class, not an instance
        Always subclass GenerateJsonSchema and pass the class to Pydantic, not an instance
        :return: The generated connector schema as a dictionary.
        """
        connector_name = self.connector_name
        flatten_config_loader_schema = self.flatten_config_loader_schema

        class ConnectorConfigSchemaGenerator(GenerateJsonSchema):
            def generate(self, schema, mode="validation"):
                json_schema = super().generate(schema, mode=mode)

                if json_schema["title"] == "ConfigLoader":
                    json_schema["$schema"] = self.schema_dialect
                    json_schema["$id"] = f"https://www.filigran.io/connectors/{connector_name}_config_vars.schema.json"
                    return flatten_config_loader_schema(json_schema, self.definitions)

                return json_schema

        return self.connector_config_loader.model_json_schema(
            by_alias=True, schema_generator=ConnectorConfigSchemaGenerator
        )

    def create_connector_config_json_schema(self):
        """
        Generates the connector contract and writes it to a JSON file.
        """
        connector_config_json_schema = self.generate_connector_config_vars_schema()

        filepath = os.path.join(os.path.dirname(__file__), "__metadata__", __CONNECTOR_CONFIG_JSON_SCHEMA_FILENAME__)
        with open(filepath, "w") as file:
            connector_config_json_schema_json = json.dumps(connector_config_json_schema, indent=2)
            file.write(connector_config_json_schema_json)

        print(f"✅- Connector contract written to {filepath}")


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
