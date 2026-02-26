import json
import os
import re
import traceback
from dataclasses import asdict, dataclass, field, fields
from datetime import date
from functools import lru_cache
from pathlib import Path
from typing import Literal

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
    """
    Define and validate fields of a connector's manifest.
    """

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
        """
        Check that every field has a value.
        All fields are required to validate the instance (even if the default is None).
        """
        for field_info in fields(self):
            if (
                getattr(self, field_info.name) is None
                and field_info.default is not None
            ):
                raise ValueError(
                    f"Field {field_info.name} is required and cannot be None"
                )

    def to_json(self) -> dict:
        """
        Convert the instance to a JSON serializable dict.
        """
        manifest_dict = asdict(self)
        manifest_dict["last_verified_date"] = (
            self.last_verified_date.isoformat() if self.last_verified_date else None
        )

        return manifest_dict


class ConnectorManifestBuilder:
    """
    Build a connector's manifest based on connector's directory.
    It uses the directory path, directory name, `__metadata__` subdirectory and `README.md`.
    It will write `__metadata__/connector_manifest.json` on disk.
    """

    def __init__(self, directory_path: str):
        """
        Init a `ConnectorManifestBuilder` instance.
        :param directory_path: Directory path of a connector, e.g. "external-import/cve" for the CVE connector.
        """
        self.directory_path = directory_path

    @property
    def manifest_title(self) -> str:
        """
        Return value for `connector_manifest["title"]`.
        """
        directory_name = os.path.basename(self.directory_path)
        return directory_name.replace("-", " ").title()

    @property
    def manifest_slug(self) -> str:
        """
        Return value for `connector_manifest["slug"]`.
        """
        directory_name = os.path.basename(self.directory_path)
        return directory_name

    @property
    def manifest_source_code(self) -> str:
        """
        Return value for `connector_manifest["source_code"]`.
        """
        parent_directory_name = os.path.basename(os.path.dirname(self.directory_path))
        directory_name = os.path.basename(self.directory_path)
        return f"https://github.com/OpenCTI-Platform/connectors/tree/release/6.9.x/{parent_directory_name}/{directory_name}"

    @property
    def manifest_container_image(self) -> str:
        """
        Return value for `connector_manifest["container_image"]`.
        """
        directory_name = os.path.basename(self.directory_path)
        return f"opencti/connector-{directory_name}"

    @property
    def manifest_container_type(self) -> str:
        """
        Return value for `connector_manifest["container_type"]`.
        """
        parent_directory_name = os.path.basename(os.path.dirname(self.directory_path))
        return parent_directory_name.upper().replace("-", "_")

    @property
    def manifest_logo(self) -> str | None:
        """
        Return value for `connector_manifest["logo"]`.
        """
        connector_metadata_directory_path = (
            Path(self.directory_path) / CONNECTOR_METADATA_DIRECTORY
        )
        if os.path.exists(connector_metadata_directory_path):
            files = os.listdir(connector_metadata_directory_path)
            for file in files:
                if file.startswith("logo."):
                    logo_path = (
                        Path(self.directory_path) / CONNECTOR_METADATA_DIRECTORY / file
                    )
                    return logo_path.as_posix()

        return None

    @property
    def manifest_description(self) -> str:
        """
        Return value for `connector_manifest["description"]` and `connector_manifest["short_description"]`.
        Try to get description from connector's README, otherwise return the default.
        """
        return self._get_readme_description() or "Information coming soon"

    @property
    def manifest_last_verified_date(self) -> date | None:
        """
        Return value for `connector_manifest["verified"]` and `connector_manifest["last_verified_date"]`.
        Try to get verification info from connector's README, otherwise return `None`.
        """
        last_verified_iso = self._get_readme_last_verified_date()
        if last_verified_iso:
            return date.fromisoformat(last_verified_iso)
        return None

    @lru_cache
    def _parse_readme(self) -> dict | None:
        """
        Parse connector's README as AST.
        Use cache to avoid re-open and parse the same README file multiple times.
        """
        readme_path = Path(self.directory_path) / "README.md"
        if os.path.exists(readme_path):
            with open(readme_path, "r", encoding="utf-8") as file:
                readme_content = file.read()
                markdown_parser = mistune.create_markdown(renderer="ast")
                ast = markdown_parser(readme_content)
                return ast

        return None

    def _get_readme_description(self) -> str | None:
        """
        Try to find the connector's description by browsing the first sections of its README,
        otherwise return `None`.
        """

        def get_node_text_recursively(node):
            in_verified_table = any(
                [
                    child
                    for child in node.get("children", [])
                    if "|FiligranVerified|" in "".join(child.get("raw", "").split())
                ]
            )
            if in_verified_table:
                return []

            paragraphs = []
            if node.get("children", []):
                for child in node.get("children", []):
                    paragraphs.extend(get_node_text_recursively(child))
            elif node.get("type") == "blank_line":
                paragraphs.append("\n")
            elif node.get("raw") and node.get("raw") != "Table of Contents":
                paragraphs.append(node.get("raw"))

            return paragraphs

        readme_ast = self._parse_readme()
        if not readme_ast:
            return None

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
                    node_text = get_node_text_recursively(node)
                    paragraphs.extend(node_text)

        return "".join(paragraphs).strip() or None

    def _get_readme_last_verified_date(self) -> str | None:
        """
        Try to find the connector's verification status by browsing its README,
        otherwise return `None`.
        """

        def get_node_text_recursively(node):
            last_verified_row = next(
                (
                    "".join(child.get("raw", "").split())  # raw without whitespaces
                    for child in reversed(node.get("children", []))
                    if "|FiligranVerified|" in "".join(child.get("raw", "").split())
                ),
                None,
            )
            if not last_verified_row:
                if node.get("children", []):
                    for child in node.get("children", []):
                        last_verified_row = get_node_text_recursively(child)
                        if last_verified_row:
                            break

            if last_verified_row:
                last_verified_date_match = re.search(
                    r"\|20[0-9]{2}-[0-9]{2}-[0-9]{2}\|",
                    last_verified_row,
                )
                last_verified_date_match = (
                    last_verified_date_match.group()
                    if last_verified_date_match
                    else None
                )
                if last_verified_date_match:
                    last_verified_iso = last_verified_date_match.replace("|", "")
                    if last_verified_iso:
                        return last_verified_iso

        readme_ast = self._parse_readme()
        if not readme_ast:
            return None

        for node in readme_ast:
            last_verified_iso = get_node_text_recursively(node)
            if last_verified_iso:
                return last_verified_iso

    def _get_current_manifest_data(self) -> dict | None:
        """
        Parse current connector's manifest if it exists on disk, otherwise return `None`.
        """
        manifest_path = (
            Path(self.directory_path)
            / CONNECTOR_METADATA_DIRECTORY
            / CONNECTOR_MANIFEST_FILENAME
        )
        if os.path.exists(manifest_path):
            with open(manifest_path, "r", encoding="utf-8") as file:
                manifest = json.load(file)
                return manifest

        return None

    def _build_manifest(self) -> ConnectorManifest:
        """
        Build the connector's manifest.
        If a manifest exists on disk, it will be updated when necessary.
        """
        manifest_data = self._get_current_manifest_data() or {}

        manifest_data.update(
            title=manifest_data.get("title") or self.manifest_title,
            slug=manifest_data.get("slug") or self.manifest_slug,
            description=(
                manifest_data.get("description")
                if manifest_data.get("description")
                and manifest_data.get("description") != "Information coming soon"
                else self.manifest_description
            ),
            short_description=(
                manifest_data.get("short_description")
                if manifest_data.get("short_description")
                and manifest_data.get("short_description") != "Information coming soon"
                else self.manifest_description
            ),
            logo=self.manifest_logo,
            verified=(
                manifest_data.get("verified")
                if manifest_data.get("verified") is not None
                else bool(self.manifest_last_verified_date)
            ),
            last_verified_date=(
                date.fromisoformat(manifest_data.get("last_verified_date"))
                if manifest_data.get("last_verified_date")
                else self.manifest_last_verified_date
            ),
            source_code=manifest_data.get("source_code") or self.manifest_source_code,
            container_image=(
                manifest_data.get("container_image") or self.manifest_container_image
            ),
            container_type=(
                manifest_data.get("container_type") or self.manifest_container_type
            ),
        )

        return ConnectorManifest(**manifest_data)

    def create_manifest(self):
        """
        Build the connector's manifest and write it on disk (`__metadata__/connector_manifest.json`).
        """
        connector_manifest = self._build_manifest()

        # Ensure __metadata__ directory exists before creating the manifest file
        Path.mkdir(
            self.directory_path / CONNECTOR_METADATA_DIRECTORY,
            exist_ok=True,
        )

        # Create the manifest file
        connector_manifest_file_path = (
            self.directory_path
            / CONNECTOR_METADATA_DIRECTORY
            / CONNECTOR_MANIFEST_FILENAME
        )
        with open(connector_manifest_file_path, "w", encoding="utf-8") as file:
            file.write(json.dumps(connector_manifest.to_json(), indent=2))

        print(f"✅ {connector_manifest_file_path} file created")


if __name__ == "__main__":
    """
    Entry point of the script.
    Iterate over every connector to build and save its manifest.
    """
    try:
        connectors_directories_paths = []
        for repository_subdirectory in REPOSITORY_SUBDIRECTORIES_TO_INCLUDE:
            with os.scandir(repository_subdirectory) as entries:
                for entry in entries:
                    if entry.is_dir() and not entry.name.startswith("."):
                        connector_directory_path = (
                            Path(repository_subdirectory) / entry.name
                        )
                        connectors_directories_paths.append(connector_directory_path)

        for connector_directory_path in connectors_directories_paths:
            try:
                manifest_builder = ConnectorManifestBuilder(
                    directory_path=connector_directory_path
                )
                manifest_builder.create_manifest()
            except Exception as e:
                print(
                    f"❌ Error while creating manifest for {connector_directory_path}: {e}"
                )
                traceback.print_exc()
                pass  # Skip the connector and try the next one
    except Exception:
        traceback.print_exc()
        exit(1)
