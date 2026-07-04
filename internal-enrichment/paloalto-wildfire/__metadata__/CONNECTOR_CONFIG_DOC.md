# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| PALOALTO_WILDFIRE_API_KEY | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | Palo Alto Networks WildFire API key. |
| CONNECTOR_NAME | `string` |  | string | `"Palo Alto Networks WildFire"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["StixFile", "Artifact"]` | The scope of the connector (observable types to enrich). |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| PALOALTO_WILDFIRE_API_BASE_URL | `string` |  | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | `"https://wildfire.paloaltonetworks.com/publicapi"` | WildFire API base URL (cloud region or appliance). |
| PALOALTO_WILDFIRE_SUBMIT_UNKNOWN | `boolean` |  | boolean | `false` | Submit unknown files (carried by the observable) to WildFire for analysis when no verdict exists yet. Disabled by default (opt-in): submission uploads the sample to WildFire. |
| PALOALTO_WILDFIRE_MAX_FILE_SIZE | `integer` |  | integer | `33554432` | Maximum size (in bytes) of a file the connector will download from OpenCTI and submit to WildFire. |
| PALOALTO_WILDFIRE_SUBMISSION_TIMEOUT | `integer` |  | integer | `600` | Maximum time (in seconds) to wait for a submitted file's verdict before giving up. |
| PALOALTO_WILDFIRE_MAX_TLP | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:AMBER"` | Maximum TLP of the observable the connector is allowed to enrich. |
