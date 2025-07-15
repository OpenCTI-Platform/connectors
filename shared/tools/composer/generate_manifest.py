import json
import os
from pathlib import Path

__OPENCTI_CURRENT_VERSION__ = "6.7.0"

manifest = {
    "id": "filigran-catalog-id",
    "name": "OpenCTI Connectors contracts",
    "description": "",
    "version": __OPENCTI_CURRENT_VERSION__,
    "contracts": [],
}

# Find all contracts
all_connector_schemas = []

for root, dirs, files in os.walk("."):
    for file in files:
        if file.endswith("connector_schema.json"):
            all_connector_schemas.append(os.path.join(root, file))

if not all_connector_schemas:
    print("❌ - No contract to add in manifest !")
else:
    # Add in manifest.json file
    for connector_contract in all_connector_schemas:
        with open(connector_contract, encoding="utf-8") as file:
            connector_contract_schema = json.load(file)

            # Add in manifest if and only if manager_supported=true
            if connector_contract_schema["manager_supported"]:
                # Remove unnecessary configs as XTM Composer will handle it
                del connector_contract_schema["default"]["CONNECTOR_TYPE"]
                connector_contract_schema["required"].remove("OPENCTI_URL")
                connector_contract_schema["required"].remove("OPENCTI_TOKEN")

                manifest["contracts"].append(connector_contract_schema)


# Format manifest
manifest = json.dumps(manifest, indent=2)

# Write and add manifest file in root
connector_root_path = Path(__file__).parents[3]
manifest_path = os.path.join(connector_root_path, "manifest.json")
with open(manifest_path, "w", encoding="utf-8") as manifest_file:
    manifest_file.write(manifest)
