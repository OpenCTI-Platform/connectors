connector_manifest:
	sh ./shared/tools/composer/generate_connectors_manifests/generate_connector_manifest.sh
connectors_manifests:
	sh ./shared/tools/composer/generate_connectors_manifests/generate_connectors_manifests.sh

connector_config_schema:
	sh ./shared/tools/composer/generate_connectors_config_json_schemas/generate_connector_config_json_schema.sh
connectors_config_schemas:
	sh ./shared/tools/composer/generate_connectors_config_json_schemas/generate_connectors_config_json_schemas.sh

global_manifest:
	sh ./shared/tools/composer/generate_global_manifest/generate_global_manifest.sh