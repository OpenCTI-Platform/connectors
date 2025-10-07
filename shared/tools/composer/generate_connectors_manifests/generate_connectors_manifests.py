import json
import os
import traceback
from dataclasses import asdict, dataclass, field, fields
from datetime import date
from functools import lru_cache
from pathlib import Path
from typing import Generator, Literal

import mistune

CONNECTOR_METADATA_DIRECTORY = "__metadata__"
CONNECTOR_MANIFEST_FILENAME = "connector_manifest.json"

REPOSITORY_SUBDIRECTORIES_TO_INCLUDE = [
    "external-import",
    "internal-enrichment",
    "internal-export-file",
    "internal-import-file",
    "stream",
]


@dataclass(kw_only=True)
class ConnectorManifest:
    title: str
    slug: str
    description: str = "Information coming soon"
    short_description: str = "Information coming soon"
    logo: str | None = None
    use_cases: list[str] = field(default_factory=lambda: [])
    verified: bool = False
    last_verified_date: date | None = None
    playbook_supported: bool = False
    max_confidence_level: int = 50
    support_version: str = ">=6.8.0"
    subscription_link: str | None = None
    source_code: str
    manager_supported: bool = False
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
        for field_info in fields(self):
            if (
                getattr(self, field_info.name) is None
                and field_info.default is not None
            ):
                raise ValueError(
                    f"Field {field_info.name} is required and cannot be None"
                )

        # TODO: add type checks and other validations as needed


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

                yield entry.name

    def to_manifest_title(self, connector_directory_name: str) -> str:
        return connector_directory_name.replace("-", " ").title()

    def to_manifest_container_type(
        self,
        repository_subdirectory: Literal[
            "external-import",
            "internal-enrichment",
            "internal-export-file",
            "internal-import-file",
            "stream",
        ],
    ) -> Literal[
        "EXTERNAL_IMPORT",
        "INTERNAL_ENRICHMENT",
        "INTERNAL_EXPORT_FILE",
        "INTERNAL_IMPORT_FILE",
        "STREAM",
    ]:
        return repository_subdirectory.upper().replace("-", "_")

    @lru_cache  # use cache to avoid re-open and parse the same README file multiple times
    def _parse_connector_readme(self, connector_directory_path: str) -> dict:
        readme_path = Path(connector_directory_path) / "README.md"
        if os.path.exists(readme_path):
            with open(readme_path, "r", encoding="utf-8") as file:
                readme_content = file.read()
                markdown_parser = mistune.create_markdown(renderer="ast")
                ast = markdown_parser(readme_content)
                return ast

        return None

    def get_connector_description_from_readme(
        self, connector_directory_path: str
    ) -> str:
        def get_node_text(node):
            def get_node_text_recursively(recursive_node):
                in_verified_table = any(
                    [
                        child
                        for child in recursive_node.get("children", [])
                        if "|FiligranVerified|" in "".join(child.get("raw", "").split())
                    ]
                )
                if in_verified_table:
                    return []

                paragraphs = []
                if recursive_node.get("children", []):
                    for child in recursive_node.get("children", []):
                        paragraphs.extend(get_node_text_recursively(child))
                elif recursive_node.get("type") == "blank_line":
                    paragraphs.append("\n")
                elif (
                    recursive_node.get("raw")
                    and recursive_node.get("raw") != "Table of Contents"
                ):
                    paragraphs.append(recursive_node.get("raw"))

                return paragraphs

            return get_node_text_recursively(node)

        readme_ast = self._parse_connector_readme(connector_directory_path)
        if not readme_ast:
            return ""

        # Try to find the index of description/overview section
        # If not found, start from 0 (beginning of the file)
        description_heading_index = next(
            (
                index
                for index, node in enumerate(readme_ast)
                if (
                    node["type"] == "heading"
                    and node.get("children")
                    and node.get("children")[0].get("raw", "").lower()
                    in ["description", "overwiew"]
                )
            ),
            0,
        )

        paragraphs = []
        in_description_section = False
        for node in readme_ast[description_heading_index:]:
            # Always ignore HTML blocks
            if node["type"] == "block_html":
                continue

            # Look for the description section
            if node["type"] == "heading":
                if in_description_section:
                    break  # Stop when reaching the next heading
                in_description_section = True
                continue

            # In description section, get text from nodes recursively
            if in_description_section:
                # Preserve format as much as possible
                if node["type"] == "blank_line":
                    paragraphs.append("\n")
                # Get paragrah text
                if node["type"] == "paragraph":
                    node_text = get_node_text(node)
                    paragraphs.extend(node_text)

        return "".join(paragraphs).strip()

    def build_connector_manifest(
        self, connector_directory_path: str
    ) -> ConnectorManifest:
        connector_manifest_data = {}

        # Try to get the current manifest to update it
        connector_manifest_path = (
            Path(connector_directory_path)
            / CONNECTOR_METADATA_DIRECTORY
            / CONNECTOR_MANIFEST_FILENAME
        )
        if os.path.exists(connector_manifest_path):
            with open(connector_manifest_path, "r", encoding="utf-8") as file:
                connector_manifest_data = json.load(file)

        connector_name = os.path.basename(connector_directory_path)
        connector_category = os.path.basename(os.path.dirname(connector_directory_path))

        connector_manifest_data.update(
            title=(
                connector_manifest_data.get("title")
                or self.to_manifest_title(connector_name)
            ),
            slug=connector_manifest_data.get("slug") or connector_name,
            description=(
                connector_manifest_data.get("description")
                if connector_manifest_data.get("description")
                and connector_manifest_data.get("description")
                != "Information coming soon"
                else self.get_connector_description_from_readme(
                    connector_directory_path
                )
                or "Information coming soon"
            ),
            short_description=(
                connector_manifest_data.get("short_description")
                if connector_manifest_data.get("short_description")
                and connector_manifest_data.get("short_description")
                != "Information coming soon"
                else self.get_connector_description_from_readme(
                    connector_directory_path
                )
                or "Information coming soon"
            ),
            source_code=(
                connector_manifest_data.get("source_code")
                or f"https://github.com/OpenCTI-Platform/connectors/tree/master/{connector_category}/{connector_name}"
            ),
            container_image=(
                connector_manifest_data.get("container_image")
                or f"opencti/connector-{connector_name}"
            ),
            container_type=(
                connector_manifest_data.get("container_type")
                or self.to_manifest_container_type(connector_category)
            ),
            # TODO: add default logo ?
            # TODO: add verification fields from connector's README
        )

        return ConnectorManifest(**connector_manifest_data)

    def generate_manifests(self):
        for repository_subdirectory in REPOSITORY_SUBDIRECTORIES_TO_INCLUDE:
            for connector_directory in self.get_connector_directories(
                repository_subdirectory=repository_subdirectory
            ):
                try:
                    # Build the manifest data
                    # TODO: do not overwrite existing manifest file if it is complete
                    connector_directory_path = Path(
                        Path(".") / repository_subdirectory / connector_directory
                    )
                    connector_manifest = self.build_connector_manifest(
                        connector_directory_path=connector_directory_path
                    )

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
                    with open(
                        connector_manifest_file_path, "w", encoding="utf-8"
                    ) as file:
                        connector_manifest_dict = asdict(connector_manifest)
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
