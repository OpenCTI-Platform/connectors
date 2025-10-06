import dataclasses
import json
import os
import traceback
from datetime import date
from pathlib import Path
from typing import Generator, Literal

CONNECTOR_METADATA_DIRECTORY = "__metadata__"
CONNECTOR_MANIFEST_FILENAME = "connector_manifest.json"
REPOSITORY_SUBDIRECTORIES_TO_INCLUDE = [
    "external-import",
    "internal-enrichment",
    "internal-export-file",
    "internal-import-file",
    "stream",
]


@dataclasses.dataclass(kw_only=True)
class ConnectorManifest:
    title: str
    slug: str
    description: str = "Information coming soon"
    short_description: str = "Information coming soon"
    logo: str
    use_cases: list[str]
    verified: str = False
    last_verified_date: date | None = None
    playbook_supported: str = False
    max_confidence_level: int = 50
    support_version: str = ">=6.8.0"
    subscription_link: str
    source_code: str
    manager_supported: str = False
    container_version: str = "rolling"
    container_image: str
    container_type: Literal[
        "EXTERNAL_IMPORT",
        "INTERNAL_ENRICHMENT",
        "INTERNAL_EXPORT_FILE",
        "INTERNAL_IMPORT_FILE",
        "STREAM",
    ]

    def __post_init__(self):
        # All fields are required for validation, whether the values come from init args or defaults.
        for field in dataclasses.fields(self):
            if getattr(self, field.name) is None and field.default is not None:
                raise ValueError(f"Field {field.name} is required and cannot be None")


class ConnectorsManifestsGenerator:
    def get_connector_directories(
        self,
        repository_subdirectory: Literal[
            "external-import",
            "internal-enrichment",
            "internal-export-file",
            "internal-import-file",
            "stream",
        ],
    ) -> Generator[str, None, None]:
        with os.scandir(repository_subdirectory) as entries:
            for entry in entries:
                if not entry.is_dir() or entry.name.startswith("."):
                    continue

                # TODO: to remove before merge - only for dev purposes
                connector_manifest_file_path = os.path.join(
                    ".",
                    repository_subdirectory,
                    entry.name,
                    CONNECTOR_METADATA_DIRECTORY,
                    CONNECTOR_MANIFEST_FILENAME,
                )
                if os.path.exists(connector_manifest_file_path):
                    continue  # Skip if __metadata__/connector_manifest.json already exists in connector directory

                yield entry.name

    def get_connector_manifest(self, connector_directory: str) -> ConnectorManifest:
        # TODO: get real values here - not just placeholders
        connector_manifest = ConnectorManifest(
            title=connector_directory,
            slug=connector_directory,
            logo="",
            use_cases=[],
            subscription_link="",
            source_code="",
            container_image=f"opencti/connector-{connector_directory}",
            container_type="connector_directory",
        )

        return connector_manifest

    def generate_manifests(self):
        for repository_subdirectory in REPOSITORY_SUBDIRECTORIES_TO_INCLUDE:
            for connector_directory in self.get_connector_directories(
                repository_subdirectory=repository_subdirectory
            ):
                try:
                    # Build the manifest data
                    # TODO: do not overwrite existing manifest file if it is complete

                    # Ensure __metadata__ directory exists before creating the manifest file
                    Path.mkdir(
                        connector_directory_path / CONNECTOR_METADATA_DIRECTORY,
                        exist_ok=True,
                    )

                    # Create the manifest file
                    connector_manifest_file_path = (
                        connector_directory_path
                        / CONNECTOR_METADATA_DIRECTORY
                        / CONNECTOR_MANIFEST_FILENAME
                    )
                    with open(connector_manifest_file_path, "w") as file:
                        connector_manifest = self.get_connector_manifest(
                            connector_directory
                        )
                        connector_manifest_dict = dataclasses.asdict(connector_manifest)
                        file.write(json.dumps(connector_manifest_dict, indent=2))

                    print(f"{connector_manifest_file_path} file created")
                except Exception as e:
                    print(
                        f"Error while creating manifest for {connector_directory}: {e}"
                    )
                    traceback.print_exc()
                    pass  # Skip the connector and try the next one


if __name__ == "__main__":
    """
    Entry point of the script
    """
    try:
        connectors_manifests_generator = ConnectorsManifestsGenerator()
        connectors_manifests_generator.generate_manifests()
    except Exception:
        traceback.print_exc()
        exit(1)
