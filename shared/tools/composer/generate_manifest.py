import json
import os
from pathlib import Path

__OPENCTI_CURRENT_VERSION__ = "6.7.0"
__CONNECTOR_INFOS_FILENAME__ = "connector_infos.json"
__CONNECTOR_SCHEMA_FILENAME__ = "connector_schema.json"
__CATALOG_ID__ = "filigran-catalog-id"

manifest = {
    "id": __CATALOG_ID__,
    "name": "OpenCTI Connectors contracts",
    "description": "",
    "version": __OPENCTI_CURRENT_VERSION__,
    "contracts": [],
}

# Find all connector contracts and all connector infos
all_connector_schemas = []
all_connector_infos = []

for root, dirs, files in os.walk("."):
    for file in files:
        if file.endswith(__CONNECTOR_SCHEMA_FILENAME__):
            # Gather all schema
            all_connector_schemas.append(os.path.join(root, file))
        elif file.endswith(__CONNECTOR_INFOS_FILENAME__):
            # Gather all infos
            all_connector_infos.append(os.path.join(root, file))


if not all_connector_schemas and not all_connector_infos:
    print("❌ - No contract to add in manifest !")
else:
    # Add in manifest.json file all connectors with manager supported
    for connector_contract in all_connector_schemas:
        with open(connector_contract, encoding="utf-8") as file:
            connector_contract_schema = json.load(file)

            # Add in manifest if and only if manager_supported=true
            if connector_contract_schema["manager_supported"]:
                # Remove unnecessary configs as XTM Composer will handle it
                del connector_contract_schema["default"]["CONNECTOR_TYPE"]
                del connector_contract_schema["properties"]["CONNECTOR_TYPE"]
                del connector_contract_schema["properties"]["OPENCTI_URL"]
                del connector_contract_schema["properties"]["OPENCTI_TOKEN"]
                connector_contract_schema["required"].remove("OPENCTI_URL")
                connector_contract_schema["required"].remove("OPENCTI_TOKEN")

                manifest["contracts"].append(connector_contract_schema)

    for connector_info in all_connector_infos:
        with open(connector_info, encoding="utf-8") as file:
            connector_contract_infos = json.load(file)

            # Add in manifest if and only if manager_supported=false
            # Need for XTM - HUB connectors ecosystem
            if not connector_contract_infos["manager_supported"]:
                manifest["contracts"].append(connector_contract_infos)

# Format manifest
manifest = json.dumps(manifest, indent=2)

# Write and add manifest file in root
connector_root_path = Path(__file__).parents[3]
manifest_path = os.path.join(connector_root_path, "manifest.json")
with open(manifest_path, "w", encoding="utf-8") as manifest_file:
    manifest_file.write(manifest)
