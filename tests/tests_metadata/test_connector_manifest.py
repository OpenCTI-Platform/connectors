import json
import os
from pathlib import Path

import pytest

from tests._manifest_validators import (
    is_boolean,
    is_valid_container_image,
    is_valid_container_type,
    is_valid_date_str,
    is_valid_license_type,
    is_valid_max_confidence_level,
    is_valid_solution_categories,
    is_valid_source_code,
    is_valid_str,
    is_valid_use_cases,
)

CONNECTOR_TYPES_DIRECTORIES = [
    "external-import",
    "internal-enrichment",
    "internal-export-file",
    "internal-import-file",
    "stream",
]


def get_manifests_paths() -> list[str]:
    """Return all connector manifest paths found in connector type directories."""

    manifests_paths = []
    for connector_type_directory in CONNECTOR_TYPES_DIRECTORIES:
        directory_path = Path(".") / connector_type_directory
        for entry in directory_path.iterdir():
            if entry.is_dir() and not entry.name.startswith("."):
                manifest_path = entry / "__metadata__" / "connector_manifest.json"
                if os.path.exists(manifest_path):
                    manifests_paths.append(manifest_path.as_posix())

    return manifests_paths


def load_manifest(manifest_path: str) -> dict:
    """Load a manifest from a file."""
    with open(manifest_path, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.mark.parametrize("manifest_path", get_manifests_paths())
def test_connectors_manifests_are_valid(manifest_path: str):
    """Assert that each connector manifest satisfies repository validity rules.

    Important: All fields are required. Some fields are nullable, which means
    the key is still required but the value may be `None`.

    Field validation rules:
    - title: string (required)
    - slug: string (required)
    - description: string (required)
    - short_description: string (required)
    - logo: string or None (required key, nullable value)
    - use_cases: 1-3 items from allowed use cases (required)
    - solution_categories: 1-3 items from allowed solution categories (required)
    - contact: string or None (required key, nullable value)
    - license_type: one of allowed license types (required key, nullable value)
    - verified: bool (required)
    - last_verified_date: ISO-8601 string or None (required key, nullable value)
    - playbook_supported: bool (required)
    - max_confidence_level: integer between 0 and 100 (required)
    - subscription_link: string or None (required key, nullable value)
    - source_code: Github URL (required)
    - manager_supported: bool (required)
    - container_version: string (required)
    - container_image: string with correct prefix (required)
    - container_type: correct type of connector (required)
    """

    # Given a connector manifest
    connector_manifest = load_manifest(manifest_path)

    # Then the manifest fields are valid
    assert is_valid_str(connector_manifest["title"])
    assert is_valid_str(connector_manifest["slug"])
    assert is_valid_str(connector_manifest["description"])
    assert is_valid_str(connector_manifest["short_description"])
    assert (
        is_valid_str(connector_manifest["logo"]) or connector_manifest["logo"] is None
    )
    assert is_valid_use_cases(connector_manifest["use_cases"])
    assert is_valid_solution_categories(connector_manifest["solution_categories"])
    assert (
        is_valid_str(connector_manifest["contact"])
        or connector_manifest["contact"] is None
    )
    assert (
        is_valid_license_type(connector_manifest["license_type"])
        or connector_manifest["license_type"] is None
    )
    assert is_boolean(connector_manifest["verified"])
    assert (
        is_valid_date_str(connector_manifest["last_verified_date"])
        or connector_manifest["last_verified_date"] is None
    )
    assert is_boolean(connector_manifest["playbook_supported"])
    assert is_valid_max_confidence_level(connector_manifest["max_confidence_level"])
    assert is_valid_str(connector_manifest["support_version"])
    assert (
        is_valid_str(connector_manifest["subscription_link"])
        or connector_manifest["subscription_link"] is None
    )
    assert is_valid_source_code(connector_manifest["source_code"])
    assert is_boolean(connector_manifest["manager_supported"])
    assert is_valid_str(connector_manifest["container_version"])
    assert is_valid_container_image(connector_manifest["container_image"])
    assert is_valid_container_type(connector_manifest["container_type"])
