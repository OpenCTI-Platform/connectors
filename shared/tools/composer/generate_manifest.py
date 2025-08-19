import json
import os
import traceback

__OPENCTI_CURRENT_VERSION__ = "6.7.10"
__CONNECTOR_INFOS_FILENAME__ = "connector_infos.json"
__CONNECTOR_SCHEMA_FILENAME__ = "connector_schema.json"
__CATALOG_ID__ = "filigran-catalog-id"
__CONFIG_EXCLUSION_LIST__ = ["OPENCTI_TOKEN", "OPENCTI_URL", "CONNECTOR_TYPE"]

from pathlib import Path


class ManifestGenerator:
    def __init__(self):
        self.manifest = {
            "id": __CATALOG_ID__,
            "name": "OpenCTI Connectors contracts",
            "description": "",
            "version": __OPENCTI_CURRENT_VERSION__,
            "contracts": [],
        }

    @staticmethod
    def connector_contract_paths():
        """
        Gather all connector contract paths
        """
        for root, dirs, files in os.walk("."):
            for file in files:
                if file.endswith(__CONNECTOR_SCHEMA_FILENAME__) or file.endswith(
                    __CONNECTOR_INFOS_FILENAME__
                ):
                    # Gather all schema and infos
                    connector_path = os.path.join(root, file)
                    yield connector_path

    def complete_manifest(self):
        all_contract_paths = self.connector_contract_paths()

        for connector_contract_path in all_contract_paths:
            with open(connector_contract_path, encoding="utf-8") as file:
                connector_contract = json.load(file)
                is_manager_supported = connector_contract["manager_supported"]

                if (
                    connector_contract_path.endswith(__CONNECTOR_SCHEMA_FILENAME__)
                    and is_manager_supported
                ):
                    for item in __CONFIG_EXCLUSION_LIST__:
                        # Remove unnecessary configs as XTM Composer will handle it
                        default, properties, required = (
                            connector_contract.get(k)
                            for k in ("default", "properties", "required")
                        )
                        if default.get(item):
                            del connector_contract["default"][item]
                        if properties.get(item):
                            del connector_contract["properties"][item]
                        if item in required:
                            connector_contract["required"].remove(item)
                    self.manifest["contracts"].append(connector_contract)

                if (
                    connector_contract_path.endswith(__CONNECTOR_INFOS_FILENAME__)
                    and not is_manager_supported
                ):
                    # Add in manifest if and only if manager_supported=false
                    # Need for XTM - HUB connectors ecosystem
                    self.manifest["contracts"].append(connector_contract)

    def generate_manifest(self):
        """Format, generate and write manifest"""
        self.complete_manifest()
        final_manifest = json.dumps(self.manifest, indent=2)

        # Write and add manifest file in root
        connector_root_path = Path(__file__).parents[3]
        manifest_path = os.path.join(connector_root_path, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as manifest_file:
            manifest_file.write(final_manifest)


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
