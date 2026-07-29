"""Tests for connector_config_schema.json format and business rules.

Validates JSON Schema specification compliance and connector-type-specific
invariants for every connector that ships a connector_config_schema.json.
"""

import json
import os
from pathlib import Path

import jsonschema
import pytest

CONNECTOR_TYPES_DIRECTORIES = [
    "external-import",
    "internal-enrichment",
    "internal-export-file",
    "internal-import-file",
    "stream",
]

VALID_CONNECTOR_TYPES = {
    "EXTERNAL_IMPORT",
    "INTERNAL_ENRICHMENT",
    "INTERNAL_EXPORT_FILE",
    "INTERNAL_IMPORT_FILE",
    "STREAM",
}

VALID_LOG_LEVELS = {
    "error",
    "warning",
    "warn",
    "info",
    "debug",
}


def get_config_schema_paths(connector_type: str | None = None) -> list[str]:
    """Return all connector_config_schema.json paths."""
    paths = []
    for connector_type_directory in CONNECTOR_TYPES_DIRECTORIES:
        if connector_type and connector_type_directory != connector_type:
            continue

        directory_path = Path(".") / connector_type_directory
        for entry in directory_path.iterdir():
            if entry.is_dir() and not entry.name.startswith("."):
                schema_path = entry / "__metadata__" / "connector_config_schema.json"
                if os.path.exists(schema_path):
                    paths.append(schema_path.as_posix())
    return paths


def load_schema(schema_path: str) -> dict:
    """Load a JSON schema from a file."""
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.mark.parametrize("schema_path", get_config_schema_paths())
def test_connector_config_schema_is_valid_json_schema(schema_path: str):
    """The schema must itself be valid against the JSON Schema meta-schema.

    Checks performed:
    - `$schema` references Draft 2020-12
    - Passes meta-schema validation
    - Top-level `type` is 'object'
    - `properties` is a dict
    - `required` is a list
    - `additionalProperties` is True
    """
    # Given a connector config schema
    schema = load_schema(schema_path)

    # Then the schema is a valid JSON Schema (Draft 2020-12)
    assert schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema"
    jsonschema.Draft202012Validator.check_schema(schema)

    # And the top-level structure is correct
    assert schema.get("type") == "object"
    assert isinstance(schema.get("properties"), dict)
    assert isinstance(schema.get("required"), list)
    assert schema.get("additionalProperties") is True


@pytest.mark.parametrize("schema_path", get_config_schema_paths())
def test_connector_config_schema_common_properties(schema_path: str):
    """Assert that common connector properties satisfy validity rules.

    Checks performed:
    - OPENCTI_URL: required, format 'uri'
    - OPENCTI_TOKEN: required
    - CONNECTOR_ID: not present in schema (see Note and TODO comment below)
    - CONNECTOR_NAME: optional string (non-empty default)
    - CONNECTOR_TYPE: constant (not configurable)
    - CONNECTOR_LOG_LEVEL: valid default, valid enum values when enum is defined

    Note: The connectors-sdk currently strips CONNECTOR_ID from generated schemas (filter_schema).
    It should **not** be filtered, as it is an existing property for all connectors (required for pycti).
    Unwanted fields should be filtered out on OpenCTi / XTM Hub side, not connectors-sdk.
    """
    # Given a connector config schema
    schema = load_schema(schema_path)
    properties = schema.get("properties", {})

    # Then OPENCTI_* properties are valid
    assert properties["OPENCTI_URL"].get("type") == "string"
    assert properties["OPENCTI_URL"].get("format") == "uri"
    assert properties["OPENCTI_TOKEN"].get("type") == "string"

    # And CONNECTOR_* properties are valid
    assert properties["CONNECTOR_NAME"].get("type") == "string"
    assert properties["CONNECTOR_NAME"].get("default")
    assert isinstance(properties["CONNECTOR_NAME"].get("default"), str)

    if "const" in properties["CONNECTOR_TYPE"]:
        assert properties["CONNECTOR_TYPE"].get("const")  # value checked in later tests
    else:  # i.e., when connectors-sdk is not implemented
        pytest.xfail(
            "CONNECTOR_TYPE is not defined as const, skipping const validation"
        )

    assert properties["CONNECTOR_LOG_LEVEL"].get("type") == "string"
    assert properties["CONNECTOR_LOG_LEVEL"].get("default") in VALID_LOG_LEVELS
    if "enum" in properties["CONNECTOR_LOG_LEVEL"]:
        assert set(properties["CONNECTOR_LOG_LEVEL"]["enum"]) <= VALID_LOG_LEVELS
    else:  # i.e., when connectors-sdk is not implemented
        pytest.xfail(
            "CONNECTOR_LOG_LEVEL enum is not defined, skipping enum validation"
        )

    # And required properties are correct
    required = schema.get("required", [])
    assert "OPENCTI_URL" in required
    assert "OPENCTI_TOKEN" in required
    assert "CONNECTOR_NAME" not in required
    assert "CONNECTOR_TYPE" not in required
    assert "CONNECTOR_LOG_LEVEL" not in required

    # TODO: remove properties filtering (should be filtered on OpenCTi / XTM Hub side)
    assert "CONNECTOR_ID" not in properties
    assert "CONNECTOR_ID" not in required


@pytest.mark.parametrize("schema_path", get_config_schema_paths("external-import"))
def test_external_import_connector_config_schema(schema_path: str):
    """Assert EXTERNAL_IMPORT-specific config schema rules.

    CONNECTOR_SCOPE must be defined with type 'array' and a list default.
    """
    # Given a connector config schema for an external-import connector
    schema = load_schema(schema_path)
    properties = schema.get("properties", {})

    # Then CONNECTOR_TYPE is EXTERNAL_IMPORT
    if "const" in properties["CONNECTOR_TYPE"]:
        assert properties["CONNECTOR_TYPE"]["const"] == "EXTERNAL_IMPORT"
    else:  # i.e., when connectors-sdk is not implemented
        pytest.xfail(
            "CONNECTOR_TYPE is not defined as const, skipping const validation"
        )

    # And CONNECTOR_SCOPE is an array with a list default
    assert properties["CONNECTOR_SCOPE"].get("type") == "array"
    assert isinstance(properties["CONNECTOR_SCOPE"].get("default"), list)

    # And CONNECTOR_DURATION_PERIOD is a duration string when present
    if "CONNECTOR_DURATION_PERIOD" in properties:
        assert properties["CONNECTOR_DURATION_PERIOD"].get("type") == "string"
        assert properties["CONNECTOR_DURATION_PERIOD"].get("format") == "duration"
        assert isinstance(properties["CONNECTOR_DURATION_PERIOD"].get("default"), str)
    else:  # i.e., when connectors-sdk is not implemented
        pytest.xfail(
            "CONNECTOR_DURATION_PERIOD is not defined, skipping duration validation"
        )


@pytest.mark.parametrize("schema_path", get_config_schema_paths("internal-enrichment"))
def test_internal_enrichment_connector_config_schema(schema_path: str):
    """Assert INTERNAL_ENRICHMENT-specific config schema rules.

    CONNECTOR_SCOPE must be defined with type 'array' and a non-empty list default.
    """
    # Given a connector config schema for an internal-enrichment connector
    schema = load_schema(schema_path)
    properties = schema.get("properties", {})

    # Then CONNECTOR_TYPE is INTERNAL_ENRICHMENT
    if "const" in properties["CONNECTOR_TYPE"]:
        assert properties["CONNECTOR_TYPE"]["const"] == "INTERNAL_ENRICHMENT"
    else:  # i.e., when connectors-sdk is not implemented
        pytest.xfail(
            "CONNECTOR_TYPE is not defined as const, skipping const validation"
        )

    # And CONNECTOR_SCOPE is an array of strings with a non-empty default
    assert properties["CONNECTOR_SCOPE"].get("type") == "array"
    assert properties["CONNECTOR_SCOPE"].get("items") == {"type": "string"}
    assert isinstance(properties["CONNECTOR_SCOPE"].get("default"), list)
    assert len(properties["CONNECTOR_SCOPE"]["default"]) > 0

    # And CONNECTOR_AUTO is a boolean
    assert properties["CONNECTOR_AUTO"].get("type") == "boolean"
    assert isinstance(properties["CONNECTOR_AUTO"].get("default"), bool)


@pytest.mark.parametrize("schema_path", get_config_schema_paths("internal-export-file"))
def test_internal_export_file_connector_config_schema(schema_path: str):
    """Assert INTERNAL_EXPORT_FILE-specific config schema rules.

    CONNECTOR_SCOPE must be defined with type 'array' and a non-empty list default.
    """
    # Given a connector config schema for an internal-export-file connector
    schema = load_schema(schema_path)
    properties = schema.get("properties", {})

    # Then CONNECTOR_TYPE is INTERNAL_EXPORT_FILE
    if "const" in properties["CONNECTOR_TYPE"]:
        assert properties["CONNECTOR_TYPE"]["const"] == "INTERNAL_EXPORT_FILE"
    else:  # i.e., when connectors-sdk is not implemented
        pytest.xfail(
            "CONNECTOR_TYPE is not defined as const, skipping const validation"
        )

    # And CONNECTOR_SCOPE is an array of strings with a non-empty default
    assert properties["CONNECTOR_SCOPE"].get("type") == "array"
    assert properties["CONNECTOR_SCOPE"].get("items") == {"type": "string"}
    assert isinstance(properties["CONNECTOR_SCOPE"].get("default"), list)
    assert len(properties["CONNECTOR_SCOPE"]["default"]) > 0


@pytest.mark.parametrize("schema_path", get_config_schema_paths("internal-import-file"))
def test_internal_import_file_connector_config_schema(schema_path: str):
    """Assert INTERNAL_IMPORT_FILE-specific config schema rules.

    CONNECTOR_SCOPE must be defined with type 'array' and a non-empty list default.
    """
    # Given a connector config schema for an internal-import-file connector
    schema = load_schema(schema_path)
    properties = schema.get("properties", {})

    # Then CONNECTOR_TYPE is INTERNAL_IMPORT_FILE
    if "const" in properties["CONNECTOR_TYPE"]:
        assert properties["CONNECTOR_TYPE"]["const"] == "INTERNAL_IMPORT_FILE"
    else:  # i.e., when connectors-sdk is not implemented
        pytest.xfail(
            "CONNECTOR_TYPE is not defined as const, skipping const validation"
        )

    # And CONNECTOR_SCOPE is an array of strings with a non-empty default
    assert properties["CONNECTOR_SCOPE"].get("type") == "array"
    assert properties["CONNECTOR_SCOPE"].get("items") == {"type": "string"}
    assert isinstance(properties["CONNECTOR_SCOPE"].get("default"), list)
    assert len(properties["CONNECTOR_SCOPE"]["default"]) > 0


@pytest.mark.parametrize("schema_path", get_config_schema_paths("stream"))
def test_stream_connector_config_schema(schema_path: str):
    """Assert STREAM-specific config schema rules.

    CONNECTOR_SCOPE must be defined with type 'array' and a list default.
    """
    # Given a connector config schema for a stream connector
    schema = load_schema(schema_path)
    properties = schema.get("properties", {})

    # Then CONNECTOR_TYPE is STREAM
    if "const" in properties["CONNECTOR_TYPE"]:
        assert properties["CONNECTOR_TYPE"]["const"] == "STREAM"
    else:  # i.e., when connectors-sdk is not implemented
        pytest.xfail(
            "CONNECTOR_TYPE is not defined as const, skipping const validation"
        )

    # And CONNECTOR_SCOPE is an array of strings with a list default
    assert properties["CONNECTOR_SCOPE"].get("type") == "array"
    assert properties["CONNECTOR_SCOPE"].get("items") == {"type": "string"}
    assert isinstance(properties["CONNECTOR_SCOPE"].get("default"), list)

    # And CONNECTOR_LIVE_STREAM_ID is a required string
    assert properties["CONNECTOR_LIVE_STREAM_ID"].get("type") == "string"

    # And CONNECTOR_LIVE_STREAM_LISTEN_DELETE is a boolean
    assert properties["CONNECTOR_LIVE_STREAM_LISTEN_DELETE"].get("type") == "boolean"
    assert isinstance(
        properties["CONNECTOR_LIVE_STREAM_LISTEN_DELETE"].get("default"), bool
    )

    # And CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES is a boolean
    assert properties["CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES"].get("type") == "boolean"
    assert isinstance(
        properties["CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES"].get("default"), bool
    )
