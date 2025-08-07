connectors_manifest:
	sh ./shared/tools/composer/generate_connectors_manifest.sh

connector_manifest:
	sh ./shared/tools/composer/generate_connector_manifest.sh

connector_config_schema:
	sh ./shared/tools/composer/generate_connector_config_json_schema.sh
