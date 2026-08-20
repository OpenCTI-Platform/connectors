# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | string |  |  | The API token to connect to OpenCTI. |
| REVERSINGLABS_SPECTRA_ANALYZE_URL | `string` | ✅ | string |  |  | API base URL |
| REVERSINGLABS_SPECTRA_ANALYZE_TOKEN | `string` | ✅ | string |  |  | API token |
| CONNECTOR_NAME | `string` |  | string |  | `"ReversingLabs Spectra Analyze"` | Connector name. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["Artifact", "IPv4-Addr", "Domain-Name"]` | Comma-separated list of entity types the connector will enrich. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `INTERNAL_ENRICHMENT` |  | `"INTERNAL_ENRICHMENT"` |  |
| CONNECTOR_AUTO | `boolean` |  | boolean |  | `false` | Whether the connector should run automatically when an entity is created or updated. |
| REVERSINGLABS_SPECTRA_ANALYZE_MAX_TLP | `string` |  | `TLP:WHITE` `TLP:CLEAR` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` |  | `"TLP:AMBER"` | Maximum TLP for entity that connector can enrich |
| REVERSINGLABS_SPECTRA_ANALYZE_SANDBOX_OS | `string` |  | `windows11` `windows10` `windows7` `macos11` `linux` |  | `"windows10"` | The platform to execute the sample on |
| REVERSINGLABS_SPECTRA_ANALYZE_CLOUD_ANALYSIS | `boolean` |  | boolean |  | `true` | Enable cloud analysis |
| REVERSINGLABS_URL | `string` |  | string | ⛔️ |  | Use REVERSINGLABS_SPECTRA_ANALYZE_URL instead. |
| REVERSINGLABS_TOKEN | `string` |  | string | ⛔️ |  | Use REVERSINGLABS_SPECTRA_ANALYZE_TOKEN instead. |
| REVERSINGLABS_MAX_TLP | `string` |  | `TLP:WHITE` `TLP:CLEAR` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` | ⛔️ | `"TLP:AMBER"` | Use REVERSINGLABS_SPECTRA_ANALYZE_MAX_TLP instead. |
| REVERSINGLABS_SANDBOX_OS | `string` |  | `windows11` `windows10` `windows7` `macos11` `linux` | ⛔️ | `"windows10"` | Use REVERSINGLABS_SPECTRA_ANALYZE_SANDBOX_OS instead. |
| REVERSINGLABS_CLOUD_ANALYSIS | `boolean` |  | boolean | ⛔️ | `true` | Use REVERSINGLABS_SPECTRA_ANALYZE_CLOUD_ANALYSIS instead. |
