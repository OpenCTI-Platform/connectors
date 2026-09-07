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


def get_connectors_paths() -> list[str]:
    connectors_paths = []
    for connector_type_directory in CONNECTOR_TYPES_DIRECTORIES:
        directory_path = Path(".") / connector_type_directory
        for entry in directory_path.iterdir():
            if entry.is_dir() and not entry.name.startswith("."):
                connectors_paths.append(entry.as_posix())

    return connectors_paths


@pytest.mark.parametrize("connector_path", get_connectors_paths())
def test_every_connector_contains_metadata_subdirectory(connector_path: str):
    # Given a connector path
    # When checking connector's `__metadata__` subdirectory
    # Then it should exist
    assert os.path.exists(Path(connector_path) / "__metadata__") is True


@pytest.mark.parametrize("connector_path", get_connectors_paths())
def test_every_connector_metadata_contains_connector_manifest(connector_path: str):
    # Given a connector path
    # When checking connector's `__metadata__` subdirectory
    # Then `connector_manifest.json` should exist
    assert (
        os.path.exists(
            Path(connector_path) / "__metadata__" / "connector_manifest.json"
        )
        is True
    )


@pytest.mark.parametrize("connector_path", get_connectors_paths())
def test_every_connector_metadata_contains_connector_config_schema(connector_path: str):
    # Given a connector path
    # When reading connector_manifest.json
    manifest_path = Path(connector_path) / "__metadata__" / "connector_manifest.json"
    try:
        with open(manifest_path) as f:
            manifest = json.load(f)
    except FileNotFoundError:
        pytest.fail(f"{connector_path}: connector_manifest.json not found")
    except json.JSONDecodeError as e:
        pytest.fail(f"{connector_path}: connector_manifest.json is invalid JSON: {e}")

    # Then xfail if connector is not manager_supported
    if not manifest.get("manager_supported"):
        # TODO: Remove pytest.xfail() once all connectors have a connector_config_schema.json
        pytest.xfail(
            "Connector not 'manager_supported' yet, 'connector_config_schema.json' not required"
        )

    # Or if connector is manager_supported, connector_config_schema.json must exist
    assert (
        os.path.exists(
            Path(connector_path) / "__metadata__" / "connector_config_schema.json"
        )
        is True
    )


@pytest.mark.parametrize("connector_path", get_connectors_paths())
def test_every_connector_metadata_contains_connector_logo(connector_path: str):
    # Given a connector path
    # When checking connector's `__metadata__` subdirectory
    files = os.listdir(Path(connector_path) / "__metadata__")

    logo = next((f for f in files if f.startswith("logo.")), None)

    # Then xfail if no logo is present yet
    if not logo:
        # TODO: Remove pytest.xfail() once all connectors have a logo
        pytest.xfail("No logo implemented yet")

    # Or a logo is present
    assert logo is not None
