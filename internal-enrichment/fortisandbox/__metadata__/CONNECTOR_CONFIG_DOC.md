# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Default | Description |
| -------- | ---- | -------- | --------------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  | The API token to connect to OpenCTI. |
| FORTISANDBOX_API_BASE_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | FortiSandbox base URL (appliance, VM or cloud), without the /jsonrpc suffix. |
| FORTISANDBOX_USERNAME | `string` | ✅ | string |  | FortiSandbox API username. |
| FORTISANDBOX_PASSWORD | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | FortiSandbox API password. |
| CONNECTOR_NAME | `string` |  | string | `"FortiSandbox"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string | `["StixFile", "Artifact"]` | The scope of the connector (observable types to enrich). |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean | `false` | Whether the connector should run automatically when an entity is created or updated. |
| FORTISANDBOX_API_VERSION | `string` |  | string | `"4.2.4"` | FortiSandbox JSON-RPC API version sent with every request. |
| FORTISANDBOX_SSL_VERIFY | `boolean` |  | boolean | `true` | Whether to verify the FortiSandbox TLS certificate. |
| FORTISANDBOX_SUBMIT_UNKNOWN | `boolean` |  | boolean | `true` | Submit unknown files for on-demand analysis when no verdict exists yet (requires the observable to carry an uploaded file). Enabled by default so Artifacts uploaded to OpenCTI are detonated in FortiSandbox. |
| FORTISANDBOX_MAX_FILE_SIZE | `integer` |  | integer | `33554432` | Maximum size (in bytes) of a file the connector will download from OpenCTI and submit to FortiSandbox. |
| FORTISANDBOX_SUBMISSION_TIMEOUT | `integer` |  | integer | `600` | Maximum time (in seconds) to wait for a submitted file's verdict before giving up. |
| FORTISANDBOX_MAX_TLP | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | `"TLP:AMBER"` | Maximum TLP of the observable the connector is allowed to enrich. |
