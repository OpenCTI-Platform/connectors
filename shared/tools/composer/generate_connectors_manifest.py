import json
import os
import traceback
from pathlib import Path
from typing import Generator

# ? why prefix/suffix __ ?
__OPENCTI_CURRENT_VERSION__ = "6.7.9"
__CONNECTOR_METADATA_DIRECTORY__ = "__metadata__"
__CONNECTOR_MANIFEST_FILENAME__ = "connector_manifest.json"
__CONNECTOR_CONFIG_JSON_SCHEMA_FILENAME__ = "connector_config_schema.json"
__CATALOG_ID__ = "filigran-catalog-id"


class ManifestGenerator:
    @staticmethod
    def get_connector___metadata___files_path() -> Generator[str, None, None]:
        """
        Gather all connector contract paths
        """
        for root, _, files in os.walk("."):
            if os.path.basename(root) == __CONNECTOR_METADATA_DIRECTORY__:
                connector_manifest_file_path = None
                connector_config_json_schema_file_path = None
                for file in files:
                    if file.endswith(__CONNECTOR_MANIFEST_FILENAME__):
                        connector_manifest_file_path = os.path.join(root, file)
                    if file.endswith(__CONNECTOR_CONFIG_JSON_SCHEMA_FILENAME__):
                        connector_config_json_schema_file_path = os.path.join(
                            root, file
                        )
                if (
                    connector_manifest_file_path
                    or connector_config_json_schema_file_path
                ):
                    yield (
                        connector_manifest_file_path,
                        connector_config_json_schema_file_path,
                    )

    def get_connectors_contracts(self):
        contracts = []

        for __metadata___files_paths in self.get_connector___metadata___files_path():
            manifest_file_path, config_json_schema_file_path = __metadata___files_paths

            connector_manifest = None
            connector_config_json_schema = None

            if manifest_file_path:
                with open(manifest_file_path, encoding="utf-8") as file:
                    connector_manifest = json.load(file)
            else:
                continue  # skip connectors without connector_manifest.json

            if config_json_schema_file_path:
                with open(config_json_schema_file_path, encoding="utf-8") as file:
                    connector_config_json_schema = json.load(file)

            connector_contract = connector_manifest
            if connector_config_json_schema:
                connector_contract.update(
                    {"config_schema": connector_config_json_schema}
                )

            contracts.append(connector_contract)

        return contracts

    def generate_manifest(self):
        """Format, generate and write manifest"""
        manifest = {
            "id": __CATALOG_ID__,
            "name": "OpenCTI Connectors contracts",
            "description": "",
            "version": __OPENCTI_CURRENT_VERSION__,
            "contracts": self.get_connectors_contracts(),
        }

        # Write and add manifest file in root
        connector_root_path = Path(__file__).parents[3]
        manifest_path = os.path.join(connector_root_path, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as manifest_file:
            manifest_json = json.dumps(manifest, indent=2)
            manifest_file.write(manifest_json)


if __name__ == "__main__":
    """
    Entry point of the script
    """
    try:
        manifest_generator = ManifestGenerator()
        manifest_generator.generate_manifest()
    except Exception:
        traceback.print_exc()
        exit(1)
