import json
import os
from datetime import date
from pathlib import Path

import pytest

CONNECTOR_TYPES_DIRECTORIES = [
    "external-import",
    "internal-enrichment",
    "internal-export-file",
    "internal-import-file",
    "stream",
]


def get_manifests_paths() -> list[str]:
    manifests_paths = []
    for connector_type_directory in CONNECTOR_TYPES_DIRECTORIES:
        directory_path = Path(".") / connector_type_directory
        for entry in directory_path.iterdir():
            if entry.is_dir() and not entry.name.startswith("."):
                manifest_path = entry / "__metadata__" / "connector_manifest.json"
                if os.path.exists(manifest_path):
                    manifests_paths.append(manifest_path.as_posix())

    return manifests_paths


@pytest.mark.parametrize("manifest_path", get_manifests_paths())
def test_connectors_manifests_are_valid(manifest_path: str):
    # Given a connectors' manifest path:
    with open(manifest_path, "r", encoding="utf-8") as file:
        # When reading the manifest
        connector_manifest = json.load(file)

        # Then the manifest is valid
        # Title is a str
        assert isinstance(connector_manifest["title"], str)
        # Slug is a str
        assert isinstance(connector_manifest["slug"], str)
        # Description is a str
        assert isinstance(connector_manifest["description"], str)
        # Short Description is a str
        assert isinstance(connector_manifest["short_description"], str)
        # Logo is an optional str
        assert (
            isinstance(connector_manifest["logo"], str)
            or connector_manifest["logo"] is None
        )
        # Use Cases is a list of str
        assert isinstance(connector_manifest["use_cases"], list) and all(
            isinstance(use_case, str) for use_case in connector_manifest["use_cases"]
        )
        # Verified is a bool
        assert isinstance(connector_manifest["verified"], bool)
        # Last Verified Date is an optional ISO date string
        assert (
            isinstance(connector_manifest["last_verified_date"], str)
            and date.fromisoformat(connector_manifest["last_verified_date"])
        ) or connector_manifest["last_verified_date"] is None
        # Playbook Supported is a bool
        assert isinstance(connector_manifest["playbook_supported"], bool)
        # Max Confidence Level is between 0 and 100
        assert isinstance(connector_manifest["max_confidence_level"], int) and (
            connector_manifest["max_confidence_level"] >= 0
            and connector_manifest["max_confidence_level"] <= 100
        )
        # Support Version is a str
        assert isinstance(connector_manifest["support_version"], str)
        # Subscription Link is an optional str
        assert (
            isinstance(connector_manifest["subscription_link"], str)
            or connector_manifest["subscription_link"] is None
        )
        # Source Code is a str
        assert isinstance(connector_manifest["source_code"], str) and (
            connector_manifest["source_code"].startswith(
                "https://github.com/OpenCTI-Platform/connectors/"
            )
        )
        # Manager Supported is a bool
        assert isinstance(connector_manifest["manager_supported"], bool)
        # Container Version is a str
        assert isinstance(connector_manifest["container_version"], str)
        # Container Image is a str
        assert isinstance(
            connector_manifest["container_image"], str
        ) and connector_manifest["container_image"].startswith("opencti/connector-")
        # Container Type is a literal
        assert connector_manifest["container_type"] in [
            "EXTERNAL_IMPORT",
            "INTERNAL_ENRICHMENT",
            "INTERNAL_EXPORT_FILE",
            "INTERNAL_IMPORT_FILE",
            "STREAM",
        ]
