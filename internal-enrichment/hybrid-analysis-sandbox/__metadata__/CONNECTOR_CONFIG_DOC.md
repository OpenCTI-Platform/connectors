# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  | The API token to connect to OpenCTI. |
| HYBRID_ANALYSIS_SANDBOX_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | Hybrid Analysis API token. |
| CONNECTOR_NAME | `string` |  | string |  | `"Hybrid Analysis (Sandbox Windows 10 64bit)"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["StixFile", "Artifact", "Url", "Domain-Name", "Hostname"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` |  | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean |  | `false` | Whether the connector should run automatically when an entity is created or updated. |
| HYBRID_ANALYSIS_SANDBOX_ENVIRONMENT_ID | `string` |  | `400` `310` `300` `200` `160` `120` `110` `100` |  | `"110"` | Analysis environment ID. Available values: 400=Mac Catalina 64 bit (x86), 310=Linux (Ubuntu 20.04, 64 bit), 300=Linux (Ubuntu 16.04, 64 bit), 200=Android Static Analysis, 160=Windows 10 64 bit, 120=Windows 7 64 bit, 110=Windows 7 32 bit (HWP Support), 100=Windows 7 32 bit. |
| HYBRID_ANALYSIS_SANDBOX_MAX_TLP | `string` |  | `TLP:CLEAR` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` |  | `"TLP:AMBER"` | Maximum TLP for submission. |
| HYBRID_ANALYSIS_SANDBOX_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | ⛔️ | `null` | Use HYBRID_ANALYSIS_SANDBOX_TOKEN instead. (removal scheduled for 2026-12-31) |
| HYBRID_ANALYSIS_TOKEN | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | ⛔️ |  | Use HYBRID_ANALYSIS_SANDBOX_TOKEN instead. (removal scheduled for 2026-12-31) |
| HYBRID_ANALYSIS_ENVIRONMENT_ID | `string` |  | `400` `310` `300` `200` `160` `120` `110` `100` | ⛔️ | `"110"` | Use HYBRID_ANALYSIS_SANDBOX_ENVIRONMENT_ID instead. (removal scheduled for 2026-12-31) |
| HYBRID_ANALYSIS_MAX_TLP | `string` |  | `TLP:CLEAR` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | ⛔️ | `"TLP:AMBER"` | Use HYBRID_ANALYSIS_SANDBOX_MAX_TLP instead. (removal scheduled for 2026-12-31) |
| HYBRID_ANALYSIS_API_KEY | `string` |  | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) | ⛔️ | `null` | Use HYBRID_ANALYSIS_SANDBOX_TOKEN instead. (removal scheduled for 2026-12-31) |
