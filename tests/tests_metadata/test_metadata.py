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
    # TODO: remove xfail() once every connector has its config JSON schema
    pytest.xfail(reason="Not implemented in every connector yet")

    # Given a connector path
    # When checking connector's `__metadata__` subdirectory
    # Then `connector_config_schema.json` should exist
    assert (
        os.path.exists(
            Path(connector_path) / "__metadata__" / "connector_config_schema.json"
        )
        is True
    )


@pytest.mark.parametrize("connector_path", get_connectors_paths())
def test_every_connector_metadata_contains_connector_logo(connector_path: str):
    # TODO: remove xfail() once every connector has its logo
    pytest.xfail(reason="Not implemented in every connector yet")

    # Given a connector path
    # When checking connector's `__metadata__` subdirectory
    files = os.listdir(Path(connector_path) / "__metadata__")

    # Then a `logo.*` file should exist (extension doesn't matter)
    assert any([file.startswith("logo.") for file in files]) is True
