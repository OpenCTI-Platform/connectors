import json
import os
from pathlib import Path

import pytest

CONNECTOR_TYPES_DIRECTORIES = [
    "external-import",
    "internal-enrichment",
    "internal-export-file",
    "internal-import-file",
    "stream",
]


def get_config_schemas_paths() -> list[str]:
    config_schemas_paths = []
    for connector_type_directory in CONNECTOR_TYPES_DIRECTORIES:
        directory_path = Path(".") / connector_type_directory
        for entry in directory_path.iterdir():
            if entry.is_dir() and not entry.name.startswith("."):
                config_schema_path = (
                    entry / "__metadata__" / "connector_config_schema.json"
                )
                if os.path.exists(config_schema_path):
                    config_schemas_paths.append(config_schema_path.as_posix())

    return config_schemas_paths


@pytest.mark.parametrize("config_schema_path", get_config_schemas_paths())
def test_connectors_config_schemas_are_valid(config_schema_path: str):
    connector_directory_name = Path(config_schema_path).parents[1].name

    # Given a connectors' config schema path:
    with open(config_schema_path, "r", encoding="utf-8") as file:
        # When reading the config schema
        connector_config_schema = json.load(file)

        assert (
            connector_config_schema["$schema"]
            == "https://json-schema.org/draft/2020-12/schema"
        )
        assert (
            connector_config_schema["$id"]
            == f"https://www.filigran.io/connectors/{connector_directory_name}_config.schema.json"
        )
        assert connector_config_schema["type"] == "object"
        assert isinstance(connector_config_schema["properties"], dict)
        assert isinstance(connector_config_schema["required"], list) and all(
            isinstance(property, str)
            for property in connector_config_schema["required"]
        )
        assert connector_config_schema["additionalProperties"] is True
